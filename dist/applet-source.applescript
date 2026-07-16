-- MacTriage launcher: double-click the .app to run the bundled mactriage
-- binary in a fresh Terminal window.
--
-- It opens Contents/Resources/run-mactriage.command via `open` (LaunchServices)
-- instead of `tell application "Terminal" ... do script`. That deliberately
-- avoids sending Apple events to Terminal, so the app needs NO Automation
-- permission and never hits the "-1743 Not authorized to send Apple events"
-- error. The sudo flow lives in run-mactriage.command.
on run
	set cmdPath to POSIX path of (path to me) & "Contents/Resources/run-mactriage.command"
	do shell script "/usr/bin/open -a Terminal " & quoted form of cmdPath
end run
