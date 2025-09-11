JADX_EXTRACT_APP_NAME = """
If you need to find the name of the app opened in JADX:
1) Call the MCP tool `get_android_manifest` to obtain the AndroidManifest.xml.
2) Extract the package from <manifest package="...">.
3) Find the app name:
   - If <application android:label="..."> is a literal string, use it.
   - If it is a reference like @string/xxx, call `get_strings()` and resolve the key.
4) If no valid label is found, return the package as a fallback for app_name.
Respond exclusively by populating the output schema.
"""