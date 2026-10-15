import { loadOperator } from './operator.js';

document.querySelectorAll('.operator-menu').forEach(menu => {
  menu.addEventListener('focusout', event => {
    if (!menu.contains(event.relatedTarget)) menu.open = false;
  });
  document.addEventListener('pointerdown', event => {
    if (!menu.contains(event.target)) menu.open = false;
  });
  menu.addEventListener('keydown', event => {
    if (event.key === 'Escape') {
      menu.open = false;
      menu.querySelector('summary').focus();
    }
  });
  window.addEventListener('blur', () => { menu.open = false; });
});

const operatorLabel = document.getElementById('operator');
if (operatorLabel) {
  loadOperator().then(operator => {
    operatorLabel.textContent = operator
      ? `${operator.username} (${operator.role === 'admin' ? 'Администратор' : 'Наблюдатель'})`
      : 'Не удалось загрузить оператора';
  });
}
