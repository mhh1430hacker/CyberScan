@echo off
rem Double-click: upload the current project to AWS (S3 + Lambda + CloudFront, all three domains).
cd /d "%~dp0"
python tools\deploy\deploy_aws.py %*
echo.
pause
