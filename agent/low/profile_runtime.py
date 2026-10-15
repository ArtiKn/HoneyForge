"""Atomic lifecycle for the Agent's active Trap Profile."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Protocol


class TrapService(Protocol):
    async def prepare(self) -> None: ...

    async def start_accepting(self) -> None: ...

    def commit(self) -> None: ...

    async def stop_accepting(self) -> None: ...

    async def wait_drained(self) -> None: ...

    async def stop(self) -> None: ...


class ProfileApplyError(RuntimeError):
    """A candidate Trap Profile could not replace the active version."""


class HealthReporter(Protocol):
    async def report_health(
        self, queue: Any, *, agent_version: str, active_profile_version: int,
        enabled: bool, configuration_errors: list[str],
    ) -> None: ...


async def report_runtime_health(
    reporter: HealthReporter,
    queue: Any,
    runtime: "ProfileRuntime",
    *,
    agent_version: str,
) -> None:
    """Report the active version and apply state through the Agent health seam."""
    await reporter.report_health(
        queue,
        agent_version=agent_version,
        active_profile_version=runtime.active_profile_version,
        enabled=runtime.enabled,
        configuration_errors=runtime.configuration_errors,
    )


class ProfileRuntime:
    """Keep one last-known-good service set active across profile changes."""

    def __init__(
        self, build_services: Callable[[dict[str, Any]], list[TrapService]]
    ) -> None:
        self._build_services = build_services
        self._active_configuration: dict[str, Any] | None = None
        self._active_services: list[TrapService] = []
        self._enabled = True
        self._retirement_tasks: set[asyncio.Task[None]] = set()
        self._configuration_errors: list[str] = []
        self._retirement_errors: list[str] = []

    @property
    def active_profile_version(self) -> int:
        if self._active_configuration is None:
            raise RuntimeError("No Trap Profile is active")
        return int(self._active_configuration["profile_version"])

    @property
    def enabled(self) -> bool:
        """Whether the active Trap Profile's services are currently accepting."""

        return self._enabled

    @property
    def configuration_errors(self) -> list[str]:
        return [*self._configuration_errors, *self._retirement_errors]

    async def start(self, configuration: dict[str, Any]) -> None:
        if self._active_configuration is not None:
            raise RuntimeError("A Trap Profile is already active")
        enabled = bool(configuration.get("enabled", True))
        services = self._build_services(configuration)
        if enabled:
            try:
                await self._activate(services)
            except Exception:
                for service in services:
                    await service.stop()
                raise
            self._active_services = services
        else:
            for service in services:
                await service.stop()
            self._active_services = []
        self._active_configuration = configuration
        self._enabled = enabled
        self._configuration_errors = []

    async def refresh(
        self, fetch_configuration: Callable[[], Awaitable[dict[str, Any]]]
    ) -> bool:
        try:
            changed = await self.apply(await fetch_configuration())
        except Exception as exc:
            self._configuration_errors = [str(exc)]
            raise
        self._configuration_errors = []
        return changed

    async def apply(self, configuration: dict[str, Any]) -> bool:
        if self._active_configuration is None:
            await self.start(configuration)
            return True
        try:
            candidate_version = int(configuration["profile_version"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfileApplyError(f"Invalid Trap Profile: {exc}") from exc
        candidate_enabled = bool(configuration.get("enabled", True))
        if candidate_version <= self.active_profile_version:
            if (
                candidate_version == self.active_profile_version
                and candidate_enabled != self._enabled
            ):
                if candidate_enabled:
                    await self._enable(configuration)
                else:
                    await self._disable()
                self._enabled = candidate_enabled
                self._active_configuration = configuration
                return True
            return False

        if not candidate_enabled:
            if self._enabled:
                await self._disable()
            self._active_configuration = configuration
            self._enabled = False
            return True

        try:
            candidate_services = self._build_services(configuration)
        except Exception as exc:
            raise ProfileApplyError(f"Invalid Trap Profile: {exc}") from exc
        previous_services = self._active_services
        stopped_services: list[TrapService] = []
        try:
            for service in previous_services:
                await service.stop_accepting()
                stopped_services.append(service)
            await self._activate(candidate_services)
        except Exception as exc:
            cleanup_errors: list[str] = []
            for service in candidate_services:
                try:
                    await service.stop()
                except Exception as cleanup_exc:
                    cleanup_errors.append(str(cleanup_exc))
            try:
                await self._activate(stopped_services)
            except Exception as rollback_exc:
                cleanup_errors.append(f"last-known-good restart failed: {rollback_exc}")
            detail = "; ".join([str(exc), *cleanup_errors])
            if cleanup_errors:
                raise ProfileApplyError(
                    detail
                ) from exc
            raise ProfileApplyError(str(exc)) from exc

        for service in previous_services:
            task = asyncio.create_task(self._retire(service))
            self._retirement_tasks.add(task)
            task.add_done_callback(self._retirement_finished)
        self._active_services = candidate_services
        self._active_configuration = configuration
        self._enabled = True
        return True

    async def _enable(self, configuration: dict[str, Any]) -> None:
        """Start accepting again from the active Trap Profile."""

        try:
            services = self._build_services(configuration)
        except Exception as exc:
            raise ProfileApplyError(f"Invalid Trap Profile: {exc}") from exc
        try:
            await self._activate(services)
        except Exception as exc:
            raise ProfileApplyError(str(exc)) from exc
        self._active_services = services
        self._configuration_errors = []

    async def _disable(self) -> None:
        """Stop accepting while keeping the Agent and its buffer delivery alive."""

        previous_services = self._active_services
        self._active_services = []
        for service in previous_services:
            try:
                await service.stop_accepting()
            except Exception:
                pass
        for service in previous_services:
            task = asyncio.create_task(self._retire(service))
            self._retirement_tasks.add(task)
            task.add_done_callback(self._retirement_finished)

    async def stop(self) -> None:
        if self._retirement_tasks:
            await asyncio.gather(*self._retirement_tasks, return_exceptions=True)
        for service in self._active_services:
            await service.stop()
        self._active_services = []
        self._active_configuration = None
        self._configuration_errors = []
        self._retirement_errors = []

    def _retirement_finished(self, task: asyncio.Task[None]) -> None:
        self._retirement_tasks.discard(task)
        try:
            task.result()
        except Exception as exc:
            self._retirement_errors.append(f"Trap service retirement failed: {exc}")

    @staticmethod
    async def _retire(service: TrapService) -> None:
        await service.wait_drained()
        await service.stop()

    @staticmethod
    async def _activate(services: list[TrapService]) -> None:
        try:
            for service in services:
                await service.prepare()
            await asyncio.gather(
                *(service.start_accepting() for service in services)
            )
            for service in services:
                service.commit()
        except Exception:
            for service in services:
                try:
                    await service.stop()
                except Exception:
                    pass
            raise
