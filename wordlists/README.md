# wordlists/

능동 정찰(vhost/DNS/디렉터리)용 워드리스트를 두는 디렉터리. 컨테이너에는 `/work/wordlists` 로
마운트된다(docker/compose.yaml). 호스트의 이 디렉터리에 넣으면 컨테이너에서 바로 쓸 수 있다.

- 파일은 줄마다 하나씩, `#` 주석 허용.
- 작은 내장 목록은 스크립트 기본값으로 있고, 실전에는 SecLists 등을 이 디렉터리에 두고
  `--wordlist wordlists/vhosts.txt` / `--dir-wordlist wordlists/dirs.txt` / `--wordlist wordlists/subdomains.txt` 로 지정.
- 주의: 이미지에 대형 워드리스트는 포함하지 않는다. 컨테이너의 gobuster 기본 경로
  (`/usr/share/wordlists/...`)는 존재하지 않으므로 **워드리스트 지정은 필수**.
