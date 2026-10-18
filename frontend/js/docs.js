const spec = await (await fetch("/openapi.json")).json();
const host = document.getElementById("api-endpoints");
for (const [path, methods] of Object.entries(spec.paths))
  for (const [method, definition] of Object.entries(methods)) {
    const section = document.createElement("details");
    section.className = "output-plugin";
    const title = document.createElement("summary");
    title.textContent = method.toUpperCase() + " " + path;
    const description = document.createElement("p");
    description.className = "hint";
    description.textContent =
      definition.description || definition.summary || "";
    const code = document.createElement("pre");
    code.className = "json-output";
    code.textContent = JSON.stringify(definition, null, 2);
    section.append(title, description, code);
    host.append(section);
  }
