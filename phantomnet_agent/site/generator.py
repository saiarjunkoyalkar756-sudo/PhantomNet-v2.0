def generate_site(launch_plan: str) -> dict:
    sections = {
        "Positioning": "",
        "Homepage Hero (copywriting)": "",
        "Pricing Page Copy": "",
        "Launch Channels": ""
    }

    current_section = None
    for line in launch_plan.splitlines():
        if line.startswith("## "):
            section_title = line[3:].strip()
            if section_title in sections:
                current_section = section_title
            else:
                current_section = None
        elif current_section:
            sections[current_section] += line + "\n"

    # Generate index.html
    index_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>PhantomNet</title>
</head>
<body>
    <h1>PhantomNet</h1>
    <h2>{sections['Homepage Hero (copywriting)'].splitlines()[0].replace('**Headline:**', '').strip()}</h2>
    <p>{sections['Homepage Hero (copywriting)'].splitlines()[1].replace('**Sub-headline:**', '').strip()}</p>
    <button>{sections['Homepage Hero (copywriting)'].splitlines()[2].replace('**CTA:**', '').strip()}</button>
</body>
</html>"""

    # Generate pricing.html
    pricing_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Pricing - PhantomNet</title>
</head>
<body>
    <h1>Pricing</h1>
    {sections['Pricing Page Copy'].strip()}
</body>
</html>"""

    # Generate contact.html
    contact_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Contact - PhantomNet</title>
</head>
<body>
    <h1>Contact Us</h1>
    <h2>Launch Channels</h2>
    <ul>
"""
    for channel in sections['Launch Channels'].splitlines():
        if channel.strip():
            contact_html += f"        <li>{channel.strip()}</li>\n"
    contact_html += """    </ul>
</body>
</html>"""

    return {
        "index.html": index_html,
        "pricing.html": pricing_html,
        "contact.html": contact_html
    }
