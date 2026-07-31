# VHS tape to generate the README demo GIF.
# Install vhs (https://github.com/charmbracelet/vhs):  go install github.com/charmbracelet/vhs@latest
# Then run:  vhs docs/demo.tape   → writes docs/demo.gif

Output docs/demo.gif
Set FontSize 14
Set Width 1100
Set Height 650
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set WindowBar Colorful

Type "urllm https://www.bsi.bund.de --json 2>/dev/null | jq '.third_parties[] | select(.is_non_eu) | .domain'"
#Type "urllm https://www.bsi.bund.de --json 2>/dev/null |jq|head -30"
Enter
Sleep 8s
Enter
Type "urllm https://www.spiegel.de --json --fail-on high; echo exit=$?"
Enter
Sleep 8s
