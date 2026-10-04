"""ztbootstrap — вспомогательные модули Bootstrap Sequence D8 (F-E-06/07/09).

Состав:
  * :mod:`ztbootstrap.manifest`  — манифест eager-загрузки и конфигурация шагов;
  * :mod:`ztbootstrap.maps`      — парсинг /proc/self/maps, baseline/diff;
  * :mod:`ztbootstrap.integrity` — измерение целостности рантайма (F-E-06);
  * :mod:`ztbootstrap.events`    — спул bootstrap-событий для WORM-аудита.

Основной оркестратор — ``bootstrap.py`` в корне подмодуля t8-sandbox.
"""
from __future__ import annotations

__version__ = "2.4.0"
