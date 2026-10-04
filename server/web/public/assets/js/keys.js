// Keyboard shortcuts: Space play/pause, ←/→ skip, Shift+←/→ chapters,
// [ / ] speed, b bookmark, s sleep timer. Ignored while typing or while a
// sheet (dialog) has focus.

import { store } from './store.js';
import { player } from './player.js';
import { toast } from './ui.js';
import { speed as fmtSpeed } from './format.js';
import { addBookmark, openSleepSheet } from './views/sheets.js';

function typing(el) {
  if (!el) return false;
  const tag = el.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el.isContentEditable;
}

export function startKeys() {
  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || typing(e.target)) return;
    if (document.querySelector('.sheet-backdrop')) return;
    if (!player.currentBookId()) return;
    const onControl = e.target && (e.target.tagName === 'BUTTON' || e.target.tagName === 'A' || e.target.getAttribute('role') === 'slider');
    switch (e.key) {
      case ' ':
      case 'Spacebar':
        if (onControl) return; // Space activates the focused button natively
        player.toggle();
        break;
      case 'ArrowLeft':
        if (e.shiftKey) player.prevChapter();
        else player.skip(-store.settings.skipBack);
        break;
      case 'ArrowRight':
        if (e.shiftKey) player.nextChapter();
        else player.skip(store.settings.skipForward);
        break;
      case '[':
      case ']':
        player.setSpeed(player.state.speed + (e.key === ']' ? 0.05 : -0.05));
        toast('Speed ' + fmtSpeed(player.state.speed), { key: 'speed', duration: 1200 });
        break;
      case 'b':
      case 'B':
        addBookmark();
        break;
      case 's':
      case 'S':
        openSleepSheet();
        break;
      default:
        return;
    }
    e.preventDefault();
  });
}
