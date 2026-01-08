#!/usr/bin/bash
set -e

docker start mailhog || true
#chmod -R 755 /var/lib/docker/volumes/mailhog_data

#source /home/admin/selenium_venv/bin/activate

/home/admin/selenium_venv/bin/python3 /home/admin/csrfScenario/autoLogin.py

