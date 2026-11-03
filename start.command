#!/bin/zsh
set -e
cd -- "${0:A:h}"
if ! command -v node >/dev/null 2>&1; then
  if [[ -s "$HOME/.nvm/nvm.sh" ]]; then
    source "$HOME/.nvm/nvm.sh"
  fi
fi
if ! command -v npm >/dev/null 2>&1; then
  print '需要 Node.js 20+。安装后重新打开本文件。'
  read '?按回车关闭…'
  exit 1
fi
if [[ ! -f node_modules/three/build/three.module.js ]]; then
  npm install --no-audit --no-fund
fi
if curl -fsS --max-time 1 http://127.0.0.1:8765/api/config >/dev/null 2>&1; then
  open http://127.0.0.1:8765
  print 'NetScope 已在运行，已打开浏览器。'
  exit 0
fi
(sleep 2; open http://127.0.0.1:8765) &
PYTHONPYCACHEPREFIX=.runtime/pycache python3 -m netshow
