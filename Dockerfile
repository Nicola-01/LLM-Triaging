FROM ubuntu:24.04
RUN apt update && apt install -y openjdk-17-jdk openjdk-21-jdk x11-apps wget unzip python3


# Install Ghidra
COPY ghidra_11.4.2_PUBLIC_20250826.zip .
# RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.4.2_build/ghidra_11.4.2_PUBLIC_20250826.zip 
RUN unzip ghidra_11.4.2_PUBLIC_20250826.zip -d /opt/ghidra && rm ghidra_11.4.2_PUBLIC_20250826.zip

# # Install Jadx
COPY jadx-1.5.3.zip .
# RUN wget https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip
RUN unzip jadx-1.5.3.zip -d /opt/jadx && rm jadx-1.5.3.zip
RUN apt install -y libcanberra-gtk-module libcanberra-gtk3-module

ENV PATH="/opt/ghidra:/opt/jadx/bin:${PATH}"

# Install Gemini CLI
RUN apt update && apt install -y nodejs npm
RUN npm install -g n
RUN n 20
RUN hash -r 

RUN npm install -g @google/gemini-cli
COPY geminiConfig.json ~/.gemini/settings.json

# Install MCP server for Jadx
WORKDIR /MCPs

RUN wget https://github.com/zinja-coder/jadx-ai-mcp/releases/download/v4.0.0/jadx-mcp-server-v4.0.0.zip 
RUN wget https://github.com/zinja-coder/jadx-ai-mcp/releases/download/v4.0.0/jadx-ai-mcp-4.0.0.jar 

RUN unzip jadx-mcp-server-v4.0.0.zip -d /MCPs/ 
RUN rm jadx-mcp-server-v4.0.0.zip 

RUN wget -qO- https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /MCPs/jadx-mcp-server

WORKDIR /opt/jadx-1.5.3/bin
RUN jadx plugins --install "github:zinja-coder:jadx-ai-mcp"


# Install GhidraMCP
WORKDIR /MCPs
RUN wget https://github.com/LaurieWired/GhidraMCP/releases/download/1.4/GhidraMCP-release-1-4.zip
RUN unzip GhidraMCP-release-1-4.zip 
RUN mv GhidraMCP-release-1-4 GhidraMCP

RUN rm GhidraMCP-release-1-4.zip


WORKDIR /

RUN apt install -y python3-pip 
RUN pip install requests mcp pyautogui --break-system-packages
RUN pip install "pydantic-ai-slim[mcp]" "pydantic-ai-slim[google]" "pydantic-ai-slim[openai]" --break-system-packages
RUN apt-get -y install python3-tk python3-dev

RUN apt install wmctrl -y

WORKDIR /workspace

CMD ["/bin/bash"]
