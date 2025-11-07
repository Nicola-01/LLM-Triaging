xhost +local:
sudo docker run -it \
  --env DISPLAY=$DISPLAY \
  --env="XAUTHORITY=$XAUTHORITY" \
  --volume="$XAUTHORITY:$XAUTHORITY" \
  --volume /tmp/.X11-unix:/tmp/.X11-unix \
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

cp oauth_creds.json ~/.gemini/oauth_creds.json && cp geminiConfig.json ~/.gemini/settings.json