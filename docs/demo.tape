# VHS tape to generate the README demo GIF.
# Install vhs (https://github.com/charmbracelet/vhs):  go install github.com/charmbracelet/vhs@latest
# Then run:  vhs docs/demo.tape   → writes docs/demo.gif

Output docs/demo.gif
Set FontSize 16
Set Width 1100
Set Height 650
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Type "urllm https://www.bahn.de --json 2>/dev/null | jq '.third_parties[] | select(.is_non_eu) | .domain'"
Enter
Sleep 6s
Type "urllm https://www.bahn.de --json --fail-on high > footprint.json; echo exit=$?"
Enter
Sleep 6s
Sleep 3s
