.\out\network-sandbox.exe start     # first run creates out\network-sandbox.json; edit it, then start again

& "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" `
    --user-data-dir="$env:TEMP\edge-sandbox" `
    --proxy-server="http://127.0.0.1:8080" `
    --no-first-run
	
# --user-data-dir is required. If Edge is already running, it hands the new 
# window to the existing process and ignores --proxy-server. A separate 
# profile forces a new process and keeps your normal browsing out of the proxy.