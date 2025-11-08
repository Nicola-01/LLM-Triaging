sudo docker build -t triage:latest .

sudo docker run -it \
  --name triage_dev \
  --env DISPLAY=$DISPLAY \
  --env="XAUTHORITY=$XAUTHORITY" \
  --volume="$XAUTHORITY:$XAUTHORITY" \
  --volume /tmp/.X11-unix:/tmp/.X11-unix \
  --volume ~/.config/jadx:/root/.config/jadx \
  --volume ~/.config/gemini:/root/.config/gemini \
  --volume .:/workspace \
  --volume ./APKs:/APKs \
  triage:latest


# One time setup:
# Gemini CLI Login
# If you want to login with google:
# First, you have to do a little trick, open gemini CLI on dokcer with the command `gemini`, and select 'Login with Google', then exit with Ctrl+C.
# Then you have to use gmeini CLI outside docker (i.e. in a machine with browser access), do the login.
# Then copy the file `~/.gemini/oauth_creds.json` into the docker container at the same path.
# $ cp oauth_creds.json ~/.gemini/oauth_creds.json

# Gemini CLI Setup MCP server
# run this command inside the docker container:
# $ cp geminiConfig.json ~/.gemini/settings.json

# cp oauth_creds.json ~/.gemini/oauth_creds.json && cp geminiConfig.json ~/.gemini/settings.json

# Ghidra MCP server setup
# Open ghidra using this command:
# $ GHIDRA_INSTALL_DIR="/opt/ghidra/ghidra_11.4.2_PUBLIC/" ./ghidra-cli
# Then follow the guide at https://github.com/LaurieWired/GhidraMCP?tab=readme-ov-file#ghidra
# The file GhidraMCP-<version>.zip is already in the docker at /MCPs/GhidraMCP/GhidraMCP-1-4.zip
# !! In point 6. of the guide, if you dont found GhidraMCPPlugin in File -> Configure -> Developer, enable it in File -> Configure -> Experimental !!
# Restart ghidra. If there is a section in the bottom, logs area like, close it with the X button. 
# Try also to open a .so file, it's possible thet there is an PopUp for the new plugin.