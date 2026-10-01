# My boss is telling me to add comment on every single line of code in this file so other people who take over my place can understand
# A green (or other colours depending on your IDE) hell for this file frfr
# A blank newline for nicer look
from flask import Flask, request, session, render_template_string, redirect, flash, send_file, abort # everything I need from Flask so far
from datetime import datetime, timezone # so I can make my status page look better
import os # I forgot what it does lol... oh wait yeah it do stuff to dirs and paths. DONT WORRY THERE IS NO `os.system` SO ITS FINE (probably)
import uuid # I heard the (not so) new UUIDv6 provides more privacy than UUIDv1, so more privacy mean more security innit.
import time # get the time, duh
import json # to dump the report dictionaries into JSON-styled str so I can then dump it into a file... wait why didn't I use dumps instead of dump..
import io # so I can do stuff to byte data without saving it <- very dangerousss
import tarfile # decompress tar duh
import zipfile # decompress zip duhhhh
import shutil # directories? NEVER HEARD OF IT SAYONARA
from threading import Thread, Lock # spawns the bot, also lock so race condition don't mess everything up
# A blank newline for nicer look
SERVER_START_TIME = time.time_ns() # Just for debug purposes so I can keep track if changes I made is optimizing the server much or less
app = Flask(__name__+uuid.uuid1().__str__()) # Creates the app duh
app.secret_key = uuid.uuid6().bytes+uuid.uuid6().bytes # Makes a random secret key
# A blank newline for nicer look
# A blank newline for nicer look
UPLOAD_FOLDER = 'uploads' # The upload folder is called `uploads`
REPORT_FOLDER = 'reports' # The report folder is called `reports`
shutil.rmtree(REPORT_FOLDER, ignore_errors=True) # Clean up the reports, **NOTE: PLEASE READ ALL REPORTS AND PROCESS THEM ACCORDINGLY BEFORE STARTING THE SERVER**
os.makedirs(UPLOAD_FOLDER, exist_ok=True) # Makes the upload folder if not already made
os.makedirs(REPORT_FOLDER, exist_ok=True) # Makes the report folder if not already made
# A blank newline for nicer look
# A blank newline for nicer look
users = { # Sets up the db (not so db its a dictionary I may regret this a few months later but idc rn)
    'admin': {'password': "Very secure password do not attempt to brute force", 'is_admin': True}, # Make the admin account first
    'bob': {'password': "BobIsVeryCool!", 'is_admin': False} # Should I not store passwords in plaintext? I should change it to hashing using hashlib later. TODO!
} # Close the curly bracket to avoid Syntax Error (Unterminated brackets or whatever that error is called)
# A blank newline for nicer look
def is_authenticated() -> bool: # Checks if a user is logged in
    return session.get('user') is not None # Aint no way someone manage to make their username `None` lol and this line is self explanatory
# A blank newline for nicer look
def is_admin() -> bool: # Checks if a user is admin
    return session.get('user') == 'admin' and users.get('admin', {}).get('is_admin', False) # rn the only admin is 'admin' so Ima hardcode it but I gave a port NOTE: Whoever takes my place replace this to `return users.get(session.get('user'), {}).get('is_admin', False)` later
# A blank newline for nicer look
def current_username() -> str: # Returns the current username
    return session.get('user') # OH MY GOD THE LINTER IS SCREAMING `ANY | NONE CANNOT ASSIGN TO RETURN TYPE STR` BUT THIS IS STR TRUST MEEEEE
# A blank newline for nicer look
report_id = 0 # how many reports have we done?
last_report_time = 0 # When was the last report done? Just storing so the health bot can see when to check if the report system is working
lock = Lock() # A lock, duh
# A blank newline for nicer look
def health_reporter() -> None: # Must be called in another thread
    global report_id, last_report_time # We need these to be changed globally
    while True: # Keep :clap: the :clap: bot :clap: running
        time.sleep(45) # Don't :clap: overload :clap: the :clap: server :clap: with :clap: this :clap: bot :clap: so :clap: we :clap: wait :clap: between each check (fr Im had enough typing all those :clap:s)
        with lock: # Just in case a report is submitted at the same time
            if time.time() - last_report_time > 60: # check per minute
                report_id += 1 # new report new report id
                last_report_time = time.time() # We reported now, update the time please
                data = { # What we put in the report
                    "reporter": "admin", # Assume its admin whos working to pretend Im doing stuff
                    "report_id": uuid.uuid6().hex, # an ID to keep track of this report in another bigger server storing reports from all apps or sth
                    "message": "automatic_health_check", # "This is a health check :3" but without the :3 maaan the world is the reason I can't be cute or sth (JUST KIDDING)
                    "timestamp": int(time.time()) # When this report is submitted
                } # Again, close the curly bracket for obvious reason
                try: # Try to submit the report
                    path = os.path.join(REPORT_FOLDER, f"{report_id}.json") # Where is the report file
                    with open(path, 'w') as f: # Lets write to that file
                        json.dump(data, f, indent=2) # woo we wrote it into the file
                    print(f"\x1b[32mHealth report submitted: {report_id}\x1b[0m") # GREEN LIGHT, YAY
                except Exception as e: # Something is bad
                    print(f"\x1b[31mHealth report failed to submit, report functionality is possibly failed: {e}\x1b[0m") # Oh no its down I dont need to review any more new reports yayyyyy (?) wait no then it mean I gotta work OT to fix this nooooo
# A blank newline for nicer look
health_reporter_thread = Thread(target=health_reporter, daemon=True) # We dont use ThreadPoolExecutor because when server die we can't forcefully kill the bot :wilted-rose:
health_reporter_thread.start() # Start the bot
# A blank newline for nicer look
# Nah fr the css is so big I gotta use some heks to let my IDE collapse it
# Btw I can't add comments for lines below cuz its a multiline string and if I add comments it would break everything cuz the comment will be considered a string instead
BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gallery - THEM?!CTF2026</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">"""+\
"""
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Inter', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            margin: 0; 
            min-height: 100vh;
            color: #333;
        }
        header { 
            background: rgba(255, 255, 255, 0.95); 
            color: #2c3e50; 
            padding: 50px 20px; 
            text-align: center; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
        }
        header h1 { 
            margin: 0; 
            font-size: 3em; 
            font-weight: 700; 
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        header p { 
            margin: 10px 0 20px; 
            font-size: 1.2em; 
            opacity: 0.8;
        }
        nav { 
            background: rgba(52, 73, 94, 0.95); 
            padding: 20px; 
            text-align: center; 
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        nav a { 
            color: #ecf0f1; 
            margin: 0 25px; 
            text-decoration: none; 
            font-weight: 500; 
            padding: 10px 20px; 
            border-radius: 25px; 
            transition: all 0.3s ease;
            display: inline-block;
        }
        nav a:hover { 
            background: rgba(255,255,255,0.2); 
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .container { 
            max-width: 1200px; 
            margin: 40px auto; 
            padding: 0 20px;
        }
        .card { 
            background: rgba(255, 255, 255, 0.95); 
            border-radius: 20px; 
            padding: 40px; 
            margin-bottom: 30px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.1); 
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.2);
            transition: transform 0.3s ease;
            box-sizing: border-box;
            overflow: hidden;
        }
        .card h2 { 
            margin-top: 0; 
            color: #2c3e50; 
            font-weight: 600;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        .flash { 
            background: linear-gradient(45deg, #e74c3c, #c0392b); 
            color: white; 
            padding: 20px; 
            border-radius: 15px; 
            margin: 20px 0; 
            box-shadow: 0 4px 15px rgba(231, 76, 60, 0.3);
            border-left: 5px solid #c0392b;
        }
        .img-wrapper {
            width: 100%;
            max-width: 240px;
            margin-right: 20px;
            flex-shrink: 0;
        }
        .img-wrapper img {
            width: 100%;
            height: auto;
            object-fit: cover;
            border-radius: 15px;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.15);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            display: block;
        }
        .img-wrapper img:hover {
            transform: scale(1.03);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
        }
        pre { 
            background: #2c3e50; 
            color: #ecf0f1; 
            padding: 25px; 
            border-radius: 15px; 
            overflow-x: auto; 
            font-family: 'Courier New', monospace;
            box-shadow: inset 0 2px 10px rgba(0,0,0,0.3);
        }
        footer { 
            text-align: center; 
            padding: 40px 20px; 
            color: rgba(255,255,255,0.8); 
            background: rgba(44, 62, 80, 0.9);
            backdrop-filter: blur(10px);
        }
        form { margin-top: 20px; }
        input, button { 
            display: block; 
            width: 25%; 
            padding: 15px; 
            margin: 10px 0; 
            border: 2px solid #ddd; 
            border-radius: 10px; 
            font-size: 16px;
            transition: all 0.3s ease;
            box-sizing: border-box;
        }
        input:focus { 
            border-color: #667eea; 
            box-shadow: 0 0 10px rgba(102, 126, 234, 0.3);
            outline: none;
        }
        button { 
            background: linear-gradient(45deg, #667eea, #764ba2); 
            color: white; 
            border: none; 
            cursor: pointer; 
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            width: auto;
            max-width: 100%;
        }
        button:hover { 
            background: linear-gradient(45deg, #5a67d8, #6b46c1); 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }
        ul { list-style: none; padding: 0; }
        li { 
            background: rgba(102, 126, 234, 0.1); 
            margin: 10px 0; 
            padding: 20px; 
            border-radius: 10px; 
            border-left: 4px solid #667eea;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.3s ease;
            flex-wrap: wrap;
        }
        li:hover { background: rgba(102, 126, 234, 0.2); }
        li strong { font-weight: 600; color: #2c3e50; }
        li form { 
            margin: 0; 
            flex: 1 1 auto;
            text-align: right;
        }
        li a, li button { 
            background: #27ae60; 
            color: white; 
            padding: 8px 16px; 
            border-radius: 20px; 
            text-decoration: none; 
            font-size: 14px;
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            width: auto;
            max-width: 100%;
            white-space: nowrap;
        }
        li a:hover, li button:hover { 
            background: #229954; 
            transform: scale(1.05);
        }
        .lightbox-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0, 0, 0, 0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.3s ease;
        }
        .lightbox-overlay.active {
            opacity: 1;
            pointer-events: all;
        }
        .lightbox-overlay img {
            max-width: 90vw;
            max-height: 90vh;
            border-radius: 10px;
            box-shadow: 0 0 40px rgba(0, 0, 0, 0.5);
            object-fit: contain;
            cursor: zoom-out;
            transition: transform 0.3s ease;
        }
        .gallery {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 20px;
            list-style: none;
            padding: 0;
        }
        .gallery-item {
            position: relative;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 6px 20px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }
        .gallery-item:hover {
            transform: translateY(-5px);
        }
        .gallery-item img {
            width: 100%;
            height: 200px;
            object-fit: cover;
            display: block;
            cursor: zoom-in;
            transition: transform 0.3s ease;
        }
        .gallery-item .overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.8);
            z-index: 999;
            opacity: 0;
            transition: opacity 0.3s ease;
            pointer-events: none;
        }
        .gallery-item:hover .overlay {
            opacity: 1;
        }
        .gallery-item img:hover {
            transform: scale(1.05);
        }
        .gallery-item .report-btn {
            position: absolute;
            bottom: 10px;
            right: 10px;
            background: rgba(231, 76, 60, 0.9);
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 20px;
            cursor: pointer;
            font-size: 12px;
            transition: background 0.3s ease;
        }
        .gallery-item .report-btn:hover {
            background: rgba(192, 57, 43, 0.9);
        }
        .gallery-item .report-btn:hover ~ .overlay {
            opacity: 0;
        }
        @media (max-width: 768px) {
            .gallery {
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: 15px;
            }
            .gallery-item img {
                height: 150px;
            }
        }
    </style>"""+\
"""
</head>
<body>
    <header>
        <h1>Gallery</h1>
        <p>(Not so) Secure photo storing & sharing platform</p>
    </header>
    <!-- the nav bar duhhhh-->
    <nav>
        <a href="/">Home</a>
        {% if current_username %}
            <a href="/upload">Upload</a>
            <a href="/logout">Logout ({{ current_username }})</a>
        {% else %}
            <a href="/login">Login</a>
            <a href="/register">Register</a>
        {% endif %}
    </nav>
    <div class="container">
        <!--loop thru flashes in case the user SOMEHOW buffered multiple flashes (?????)-->
        {% for msg in get_flashed_messages() %}
            <div class="flash">{{ msg }}</div>
        {% endfor %}
        {{ content | safe }}
    </div>
    <!--small trick to make that image enlarge thingy-->
    <div class="lightbox-overlay" id="lightbox">
        <img src="" alt="Expanded Image">
    </div>
    <footer>© 2026 THEM?!CTF - Gallery, All Rights Reserved (?)</footer>
    <!--and I will oneline and hide this ugly part lmaooo-->
    <script>document.addEventListener("DOMContentLoaded", () => {const lightbox = document.getElementById("lightbox");const lightboxImg = lightbox.querySelector("img");document.querySelectorAll(".gallery-item img").forEach(img => {img.addEventListener("click", () => {lightboxImg.src = img.src;lightbox.classList.add("active");});});lightbox.addEventListener("click", () => {lightbox.classList.remove("active");lightboxImg.src = "";});document.addEventListener("keydown", (e) => {if (e.key === "Escape") lightbox.classList.remove("active");});document.querySelectorAll('.gallery-item .report-btn').forEach(btn => {btn.addEventListener('mouseenter', () => {btn.closest('.gallery-item').querySelector('.overlay').style.opacity = '0';});btn.addEventListener('mouseleave', () => {btn.closest('.gallery-item').querySelector('.overlay').style.opacity = '';});});});</script>
</body>
</html>
""" # Forgive me boss I REALLY can't help it, yk this is how python works its not that I can change it or sth
# A blank newline for nicer look
# A blank newline for nicer look
@app.route('/') # The page for `http(s): //this_site/`
def index(): # It takes no argument because why do you need argument for index page
    pictures = [os.path.join(d, f) for d in os.listdir(UPLOAD_FOLDER) for f in (os.listdir(os.path.join(UPLOAD_FOLDER, d)) if os.path.isdir(os.path.join(UPLOAD_FOLDER, d)) else [])] # (Not so) tidy oneliner to grab all the pics in upload folder
    gallery_html = "" # The html code of all the pictures
    for img in pictures: # For each picture
        gallery_html += f"""
        <div class="gallery-item">
            <div class="overlay"></div>
            <img src="./{UPLOAD_FOLDER}/{img}" alt="{img}, uploaded by {img.split(os.sep)[0]}" id="{uuid.uuid1().hex}">
            <form method="post" action="/report/{img}" style="display: inline;">
                <button type="submit" class="report-btn">Report</button>
            </form>
        </div>""" # We append its code
    # A blank newline for nicer look
    content = f"""
    <div class="card">
        <h2>Uploaded Pictures</h2>
        <div class="gallery">{gallery_html or '<p>No pictures uploaded yet.</p>'}</div>
        <p>Only administrators can upload pictures for now due to security reasons</p>
    </div>
    """ # we blanket it with the actual content code
    return render_template_string(BASE_TEMPLATE, content=content, current_username=current_username(), is_admin=is_admin()) # and then we render it
# A blank newline for nicer look
@app.route('/status') # The page for `http(s)://this_site/status`
def status(): # It also takes no argument because they are just here for the status
    if not is_authenticated(): # If the user is not logged in
        flash("Please log in to view the status page. (Please don't ask why)") # Tell them to log in
        return redirect('/login') # Bye bye
    start = time.time_ns() # health check :p
    for n in range(100000): # no copy and paste use a dam loop
        n = n+1%2==1 # do math and see how long it took
    end = time.time_ns() # measure the time
    return render_template_string( # Render the status page
        """<!DOCTYPE html>\n<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->\n<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->\n<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->\n<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->\n<head>\n<title>Gallery server status</title>\n<meta charset="UTF-8">\n<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">\n<meta http-equiv="X-UA-Compatible" content="IE=Edge">\n<meta name="robots" content="noindex, nofollow">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<style>\n.container{width:100%}.bg-white{--bg-opacity:1;background-color:#fff;background-color:rgba(255,255,255,var(--bg-opacity))}.bg-center{background-position:50%}.bg-no-repeat{background-repeat:no-repeat}.border-gray-300{--border-opacity:1;border-color:#ebebeb;border-color:rgba(235,235,235,var(--border-opacity))}.rounded{border-radius:.25rem}.border-solid{border-style:solid}.border-0{border-width:0}.border{border-width:1px}.border-t{border-top-width:1px}.cursor-pointer{cursor:pointer}.block{display:block}.inline-block{display:inline-block}.table{display:table}.hidden{display:none}.float-left{float:left}.clearfix:after{content:"";display:table;clear:both}.font-mono{font-family:monaco,courier,monospace}.font-light{font-weight:300}.font-normal{font-weight:400}.font-semibold{font-weight:600}.h-12{height:3rem}.h-20{height:5rem}.text-13{font-size:13px}.text-15{font-size:15px}.text-60{font-size:60px}.text-2xl{font-size:1.5rem}.text-3xl{font-size:1.875rem}.leading-tight{line-height:1.25}.leading-normal{line-height:1.5}.leading-relaxed{line-height:1.625}.leading-1\\.3{line-height:1.3}.my-8{margin-top:2rem;margin-bottom:2rem}.mx-auto{margin-left:auto;margin-right:auto}.mr-2{margin-right:.5rem}.mb-2{margin-bottom:.5rem}.mt-3{margin-top:.75rem}.mb-4{margin-bottom:1rem}.ml-4{margin-left:1rem}.mt-6{margin-top:1.5rem}.mb-6{margin-bottom:1.5rem}.mb-8{margin-bottom:2rem}.mb-10{margin-bottom:2.5rem}.ml-10{margin-left:2.5rem}.mb-15{margin-bottom:3.75rem}.-ml-6{margin-left:-1.5rem}.overflow-hidden{overflow:hidden}.p-0{padding:0}.py-2{padding-top:.5rem;padding-bottom:.5rem}.px-4{padding-left:1rem;padding-right:1rem}.py-8{padding-top:2rem;padding-bottom:2rem}.py-10{padding-top:2.5rem;padding-bottom:2.5rem}.py-15{padding-top:3.75rem;padding-bottom:3.75rem}.pr-6{padding-right:1.5rem}.pt-10{padding-top:2.5rem}.absolute{position:absolute}.relative{position:relative}.left-1\\/2{left:50%}.-bottom-4{bottom:-1rem}.resize{resize:both}.text-center{text-align:center}.text-black-dark{--text-opacity:1;color:#404040;color:rgba(64,64,64,var(--text-opacity))}.text-gray-600{--text-opacity:1;color:#999;color:rgba(153,153,153,var(--text-opacity))}.text-red-error{--text-opacity:1;color:#bd2426;color:rgba(189,36,38,var(--text-opacity))}.text-green-success{--text-opacity:1;color:#9bca3e;color:rgba(155,202,62,var(--text-opacity))}.antialiased{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}.truncate{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.w-12{width:3rem}.w-240{width:60rem}.w-1\\/2{width:50%}.w-1\\/3{width:33.333333%}.w-full{width:100%}.transition{-webkit-transition-property:background-color,border-color,color,fill,stroke,opacity,box-shadow,-webkit-transform;transition-property:background-color,border-color,color,fill,stroke,opacity,box-shadow,-webkit-transform;transition-property:background-color,border-color,color,fill,stroke,opacity,box-shadow,transform;transition-property:background-color,border-color,color,fill,stroke,opacity,box-shadow,transform,-webkit-transform}body,html{--text-opacity:1;color:#404040;color:rgba(64,64,64,var(--text-opacity));-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;font-size:16px}*,body,html{margin:0;padding:0}*{box-sizing:border-box}a{--text-opacity:1;color:#2f7bbf;color:rgba(47,123,191,var(--text-opacity));text-decoration:none;-webkit-transition-property:all;transition-property:all;-webkit-transition-duration:.15s;transition-duration:.15s;-webkit-transition-timing-function:cubic-bezier(0,0,.2,1);transition-timing-function:cubic-bezier(0,0,.2,1)}a:hover{--text-opacity:1;color:#f68b1f;color:rgba(246,139,31,var(--text-opacity))}img{display:block;width:100%;height:auto}#what-happened-section p{font-size:15px;line-height:1.5}strong{font-weight:600}.bg-gradient-gray{background-image:-webkit-linear-gradient(top,#dedede,#ebebeb 3%,#ebebeb 97%,#dedede)}.cf-error-source:after{position:absolute;--bg-opacity:1;background-color:#fff;background-color:rgba(255,255,255,var(--bg-opacity));width:2.5rem;height:2.5rem;--transform-translate-x:0;--transform-translate-y:0;--transform-rotate:0;--transform-skew-x:0;--transform-skew-y:0;--transform-scale-x:1;--transform-scale-y:1;-webkit-transform:translateX(var(--transform-translate-x)) translateY(var(--transform-translate-y)) rotate(var(--transform-rotate)) skewX(var(--transform-skew-x)) skewY(var(--transform-skew-y)) scaleX(var(--transform-scale-x)) scaleY(var(--transform-scale-y));-ms-transform:translateX(var(--transform-translate-x)) translateY(var(--transform-translate-y)) rotate(var(--transform-rotate)) skewX(var(--transform-skew-x)) skewY(var(--transform-skew-y)) scaleX(var(--transform-scale-x)) scaleY(var(--transform-scale-y));transform:translateX(var(--transform-translate-x)) translateY(var(--transform-translate-y)) rotate(var(--transform-rotate)) skewX(var(--transform-skew-x)) skewY(var(--transform-skew-y)) scaleX(var(--transform-scale-x)) scaleY(var(--transform-scale-y));--transform-rotate:45deg;content:"";bottom:-1.75rem;left:50%;margin-left:-1.25rem;box-shadow:0 0 4px 4px #dedede}@media screen and (max-width:720px){.cf-error-source:after{display:none}}.cf-icon-browser{background-image:url(data:image/svg+xml;utf8,%3Csvg%20id%3D%22a%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%20100%2080.7362%22%3E%3Cpath%20d%3D%22M89.8358.1636H10.1642C4.6398.1636.1614%2C4.6421.1614%2C10.1664v60.4033c0%2C5.5244%2C4.4784%2C10.0028%2C10.0028%2C10.0028h79.6716c5.5244%2C0%2C10.0027-4.4784%2C10.0027-10.0028V10.1664c0-5.5244-4.4784-10.0028-10.0027-10.0028ZM22.8323%2C9.6103c1.9618%2C0%2C3.5522%2C1.5903%2C3.5522%2C3.5521s-1.5904%2C3.5522-3.5522%2C3.5522-3.5521-1.5904-3.5521-3.5522%2C1.5903-3.5521%2C3.5521-3.5521ZM12.8936%2C9.6103c1.9618%2C0%2C3.5522%2C1.5903%2C3.5522%2C3.5521s-1.5904%2C3.5522-3.5522%2C3.5522-3.5521-1.5904-3.5521-3.5522%2C1.5903-3.5521%2C3.5521-3.5521ZM89.8293%2C70.137H9.7312V24.1983h80.0981v45.9387ZM89.8293%2C16.1619H29.8524v-5.999h59.977v5.999Z%22%20style%3D%22fill%3A%20%23999%3B%22/%3E%3C/svg%3E)}.cf-icon-cloud{background-image:url(data:image/svg+xml;utf8,%3Csvg%20id%3D%22a%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%20152%2078.9141%22%3E%3Cpath%20d%3D%22M132.2996%2C77.9927v-.0261c10.5477-.2357%2C19.0305-8.8754%2C19.0305-19.52%2C0-10.7928-8.7161-19.5422-19.4678-19.5422-2.9027%2C0-5.6471.6553-8.1216%2C1.7987C123.3261%2C18.6624%2C105.3419.9198%2C83.202.9198c-17.8255%2C0-32.9539%2C11.5047-38.3939%2C27.4899-3.0292-2.2755-6.7818-3.6403-10.8622-3.6403-10.0098%2C0-18.1243%2C8.1145-18.1243%2C18.1243%2C0%2C1.7331.258%2C3.4033.7122%2C4.9905-.2899-.0168-.5769-.0442-.871-.0442-8.2805%2C0-14.993%2C6.7503-14.993%2C15.0772%2C0%2C8.2795%2C6.6381%2C14.994%2C14.8536%2C15.0701v.0054h.1069c.0109%2C0%2C.0215.0016.0325.0016s.0215-.0016.0325-.0016%22%20style%3D%22fill%3A%20%23999%3B%22/%3E%3C/svg%3E)}.cf-icon-server{background-image:url(data:image/svg+xml;utf8,%3Csvg%20id%3D%22a%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2095%2075%22%3E%3Cpath%20d%3D%22M94.0103%2C45.0775l-12.9885-38.4986c-1.2828-3.8024-4.8488-6.3624-8.8618-6.3619l-49.91.0065c-3.9995.0005-7.556%2C2.5446-8.8483%2C6.3295L1.0128%2C42.8363c-.3315.971-.501%2C1.9899-.5016%2C3.0159l-.0121%2C19.5737c-.0032%2C5.1667%2C4.1844%2C9.3569%2C9.3513%2C9.3569h75.2994c5.1646%2C0%2C9.3512-4.1866%2C9.3512-9.3512v-17.3649c0-1.0165-.1657-2.0262-.4907-2.9893ZM86.7988%2C65.3097c0%2C1.2909-1.0465%2C2.3374-2.3374%2C2.3374H9.9767c-1.2909%2C0-2.3374-1.0465-2.3374-2.3374v-18.1288c0-1.2909%2C1.0465-2.3374%2C2.3374-2.3374h74.4847c1.2909%2C0%2C2.3374%2C1.0465%2C2.3374%2C2.3374v18.1288Z%22%20style%3D%22fill%3A%20%23999%3B%22/%3E%3Ccircle%20cx%3D%2274.6349%22%20cy%3D%2256.1889%22%20r%3D%224.7318%22%20style%3D%22fill%3A%20%23999%3B%22/%3E%3Ccircle%20cx%3D%2259.1472%22%20cy%3D%2256.1889%22%20r%3D%224.7318%22%20style%3D%22fill%3A%20%23999%3B%22/%3E%3C/svg%3E)}.cf-icon-ok{background-image:url(data:image/svg+xml;utf8,%3Csvg%20id%3D%22a%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2048%2048%22%3E%3Ccircle%20cx%3D%2224%22%20cy%3D%2224%22%20r%3D%2223.4815%22%20style%3D%22fill%3A%20%239bca3e%3B%22/%3E%3Cpolyline%20points%3D%2217.453%2024.9841%2021.7183%2030.4504%2030.2076%2016.8537%22%20style%3D%22fill%3A%20none%3B%20stroke%3A%20%23fff%3B%20stroke-linecap%3A%20round%3B%20stroke-linejoin%3A%20round%3B%20stroke-width%3A%204px%3B%22/%3E%3C/svg%3E)}.cf-icon-error{background-image:url(data:image/svg+xml;utf8,%3Csvg%20id%3D%22a%22%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2047.9145%2047.9641%22%3E%3Ccircle%20cx%3D%2223.9572%22%20cy%3D%2223.982%22%20r%3D%2223.4815%22%20style%3D%22fill%3A%20%23bd2426%3B%22/%3E%3Cline%20x1%3D%2219.0487%22%20y1%3D%2219.0768%22%20x2%3D%2227.8154%22%20y2%3D%2228.8853%22%20style%3D%22fill%3A%20none%3B%20stroke%3A%20%23fff%3B%20stroke-linecap%3A%20round%3B%20stroke-linejoin%3A%20round%3B%20stroke-width%3A%203px%3B%22/%3E%3Cline%20x1%3D%2227.8154%22%20y1%3D%2219.0768%22%20x2%3D%2219.0487%22%20y2%3D%2228.8853%22%20style%3D%22fill%3A%20none%3B%20stroke%3A%20%23fff%3B%20stroke-linecap%3A%20round%3B%20stroke-linejoin%3A%20round%3B%20stroke-width%3A%203px%3B%22/%3E%3C/svg%3E)}#cf-wrapper .feedback-hidden{display:none}#cf-wrapper .feedback-success{min-height:33px;line-height:33px}#cf-wrapper .cf-button{color:#0051c3;font-size:13px;border-color:#0045a6;-webkit-transition-timing-function:ease;transition-timing-function:ease;-webkit-transition-duration:.2s;transition-duration:.2s;-webkit-transition-property:background-color,border-color,color;transition-property:background-color,border-color,color}#cf-wrapper .cf-button:hover{color:#fff;background-color:#003681}.cf-error-footer .hidden{display:none}.cf-error-footer .cf-footer-ip-reveal-btn{-webkit-appearance:button;-moz-appearance:button;appearance:button;text-decoration:none;background:none;color:inherit;border:none;padding:0;font:inherit;cursor:pointer;color:#0051c3;-webkit-transition:color .15s ease;transition:color .15s ease}.cf-error-footer .cf-footer-ip-reveal-btn:hover{color:#ee730a}.code-label{background-color:#d9d9d9;color:#313131;font-weight:500;border-radius:1.25rem;font-size:.75rem;line-height:4.5rem;padding:.25rem .5rem;height:4.5rem;white-space:nowrap;vertical-align:middle}@media (max-width:639px){.sm\\:block{display:block}.sm\\:hidden{display:none}.sm\\:mb-1{margin-bottom:.25rem}.sm\\:mb-2{margin-bottom:.5rem}.sm\\:py-4{padding-top:1rem;padding-bottom:1rem}.sm\\:px-8{padding-left:2rem;padding-right:2rem}.sm\\:text-left{text-align:left}}@media (max-width:720px){.md\\:border-gray-400{--border-opacity:1;border-color:#dedede;border-color:rgba(222,222,222,var(--border-opacity))}.md\\:border-solid{border-style:solid}.md\\:border-0{border-width:0}.md\\:border-b{border-bottom-width:1px}.md\\:block{display:block}.md\\:inline-block{display:inline-block}.md\\:hidden{display:none}.md\\:float-none{float:none}.md\\:text-3xl{font-size:1.875rem}.md\\:m-0{margin:0}.md\\:mt-0{margin-top:0}.md\\:mb-2{margin-bottom:.5rem}.md\\:p-0{padding:0}.md\\:py-8{padding-top:2rem;padding-bottom:2rem}.md\\:px-8{padding-left:2rem;padding-right:2rem}.md\\:pr-0{padding-right:0}.md\\:pb-10{padding-bottom:2.5rem}.md\\:top-0{top:0}.md\\:right-0{right:0}.md\\:left-auto{left:auto}.md\\:text-left{text-align:left}.md\\:w-full{width:100%}}@media (max-width:1023px){.lg\\:text-sm{font-size:.875rem}.lg\\:text-2xl{font-size:1.5rem}.lg\\:text-4xl{font-size:2.25rem}.lg\\:leading-relaxed{line-height:1.625}.lg\\:px-8{padding-left:2rem;padding-right:2rem}.lg\\:pt-6{padding-top:1.5rem}.lg\\:w-full{width:100%}}\n</style>\n</head>\n<body>\n<div id="cf-wrapper">\n    <div id="cf-error-details" class="p-0">\n        <header class="mx-auto pt-10 lg:pt-6 lg:px-8 w-240 lg:w-full mb-8">\n            <h1 class="inline-block sm:block sm:mb-2 font-light text-60 lg:text-4xl text-black-dark leading-tight mr-2">\n                <span class="inline-block">Server running fine</span>\n                <span class="code-label">Error code 200</span>\n            </h1>\n            <div class="mt-3">{{ time }}</div>\n        </header>\n        <div class="my-8 bg-gradient-gray">\n            <div class="w-240 lg:w-full mx-auto">\n                <div class="clearfix md:px-8">\n                    <div id="cf-browser-status" class=" relative w-1/3 md:w-full py-15 md:p-0 md:py-8 md:text-left md:border-solid md:border-0 md:border-b md:border-gray-400 overflow-hidden float-left md:float-none text-center">\n                        <div class="relative mb-10 md:m-0">\n                            <span class="cf-icon-browser block md:hidden h-20 bg-center bg-no-repeat"></span>\n                            <span class="cf-icon-ok w-12 h-12 absolute left-1/2 md:left-auto md:right-0 md:top-0 -ml-6 -bottom-4"></span>\n                        </div>\n                        <span class="md:block w-full truncate">You</span>\n                        <h3 class="md:inline-block mt-3 md:mt-0 text-2xl text-gray-600 font-light leading-1.3">Browser</h3>\n                        <span class="leading-1.3 text-2xl" style="color: #9bca3e">Working</span>\n                    </div>\n                    <div id="cf-cloudflare-status" class=" relative w-1/3 md:w-full py-15 md:p-0 md:py-8 md:text-left md:border-solid md:border-0 md:border-b md:border-gray-400 overflow-hidden float-left md:float-none text-center">\n                        <div class="relative mb-10 md:m-0">\n                            <span class="cf-icon-cloud block md:hidden h-20 bg-center bg-no-repeat"></span>\n                            <span class="cf-icon-ok w-12 h-12 absolute left-1/2 md:left-auto md:right-0 md:top-0 -ml-6 -bottom-4"></span>\n                        </div>\n                        <span class="md:block w-full truncate">Tharsis Montes</span>\n                        <h3 class="md:inline-block mt-3 md:mt-0 text-2xl text-gray-600 font-light leading-1.3" style="color: #2f7bbf;">not Cloudflare</h3>\n                        <span class="leading-1.3 text-2xl" style="color: #9bca3e">Working</span>\n                    </div>\n                    <div id="cf-host-status" class="cf-error-source relative w-1/3 md:w-full py-15 md:p-0 md:py-8 md:text-left md:border-solid md:border-0 md:border-b md:border-gray-400 overflow-hidden float-left md:float-none text-center">\n                        <div class="relative mb-10 md:m-0">\n                            <span class="cf-icon-server block md:hidden h-20 bg-center bg-no-repeat"></span>\n                            <span class="cf-icon-ok w-12 h-12 absolute left-1/2 md:left-auto md:right-0 md:top-0 -ml-6 -bottom-4"></span>\n                        </div>\n                        <span class="md:block w-full truncate">Website</span>\n                        <h3 class="md:inline-block mt-3 md:mt-0 text-2xl text-gray-600 font-light leading-1.3">Host</h3>\n                        <span class="leading-1.3 text-2xl" style="color: #9bca3e">Working</span>\n                    </div>\n                </div>\n            </div>\n        </div>\n        <div class="w-240 lg:w-full mx-auto mb-8 lg:px-8">\n            <div class="clearfix">\n                <div class="w-1/2 md:w-full float-left pr-6 md:pb-10 md:pr-0 leading-relaxed">\n                    <h2 class="text-3xl font-normal leading-1.3 mb-4">What happened?</h2>\n                    You came to /status to see if the website is fine. Let me tell you, if you can see this page, yes the website is fine.\n                </div>\n                <div class="w-1/2 md:w-full float-left leading-relaxed">\n                    <h2 class="text-3xl font-normal leading-1.3 mb-4">What can I do?</h2>\n                    I dont know, look at the debugging messages somewhere on this site I guess\n                </div>\n            </div>\n        </div>\n        <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">\n            <p class="text-13">\n                <span class="cf-footer-item sm:block sm:mb-1">Ray ID: <strong class="font-semibold">{{ id }}</strong></span>\n                <span class="cf-footer-separator sm:hidden">•</span>\n                <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">\n                    Your IP:\n                    <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>\n                    <span class="hidden" id="cf-footer-ip">127.0.0.1</span>\n                    <span class="cf-footer-separator sm:hidden">•</span>\n                </span>\n                <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.youtube.com/watch?v=dQw4w9WgXcQ" id="brand_link" target="_blank">your own self</a></span>\n            </p>\n        </div><!-- /.error-footer -->\n    </div>\n</div>\n<script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();console.log({{ status | safe }})</script>\n</body>\n</html>""", # Yes I also have a comment here, this is the entire status page template
        time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'), # The current time
        id = uuid.uuid1().hex[:16], # Give you an id
        status={ # Some server status info
        'server_start_time': SERVER_START_TIME, # Look up what it is up there please
        'current_time': time.time_ns(), # The current timed
        'server_uptime': time.time_ns() - SERVER_START_TIME, # How long are we not dead yet
        'health': len(str(end-start)) # health number, the lower the better
        } # Please, I said it 3 times (?) what this is for
    ) # Almost the same, but for curved bracket instead of curly bracket
# A blank newline for nicer look
@app.route('/register', methods=['GET', 'POST']) # The page for `http(s)://this_site/register`
def register(): # The arguments are handled using the POST method so no arguments here
    if is_authenticated(): # Oh you're logged in and wanna register?
        logout() # GET OUT (first, we still let you do that afterward)
    if request.method == 'POST': # If the method is POST (meaning you submitted the form)
        username = request.form['username'] # Gets your username
        password = request.form['password'] # Gets your password
        if username in users or username == 'admin': # If the username is already taken or reserved
            flash('Username taken or reserved') # Tell'em
        elif not (username and password):
            flash('Username and password required') # Tell'em
        elif not username.isalnum(): # If the username is not alphanumeric
            flash('Username must be alphanumeric') # Tell'em
        elif len(password) < 6: # If the password is too short
            flash('Password too short (min 6 characters)') # Tell'em
        else: # If its fine
            users[username] = {'password': password, 'is_admin': False} # Register the user
            flash('Registered successfully!') # Tell'em
            return redirect('/login') # Now go log in
    content = """
    <div class="card">
        <h2>Register</h2>
        <form method="post">
            <p>Username: <input name="username" required></p>
            <p>Password: <input name="password" type="password" required></p>
            <button type="submit">Register</button>
        </form>
    </div>
    """ # The form
    return render_template_string(BASE_TEMPLATE, content=content, current_username=current_username(), is_admin=is_admin()) # Renders the page
# A blank newline for nicer look
@app.route('/login', methods=['GET', 'POST']) # The page for `http(s)://this_site/login`
def login(): # The arguments are handled using the POST method so no arguments here
    if is_authenticated(): # Oh you're logged in and wanna log in again?
        logout() # GET OUT (first, we still let you do that afterward)
    if request.method == 'POST': # If the method is POST (meaning you submitted the form)
        username = request.form['username'] # Gets your username
        password = request.form['password'] # Gets your password
        user = users.get(username) # Looks up the user
        if user and user.get('password') == password: # If the user exists and the password matches
            session['user'] = username # Log you in
            flash('Logged in!') # Tell'em
            return redirect('/') # Now go play
        flash('Invalid credentials') # If we reach here the cred are wrong, tell'em
    content = """
    <div class="card">
        <h2>Login</h2>
        <form method="post">
            <p>Username: <input name="username" required></p>
            <p>Password: <input name="password" type="password" required></p>
            <button type="submit">Login</button>
        </form>
    </div>
    """ # The form
    return render_template_string(BASE_TEMPLATE, content=content, current_username=current_username(), is_admin=is_admin()) # Renders the page
    # And yes I copied most of the comments from above cuz lazy
# A blank newline for nicer look
@app.route('/logout') # The page for `http(s)://this_site/logout`
def logout(): # Why do you need arguments to log out just log out
    if session.pop('user', ''): # Tries to log out
        flash('Logged out') # If logged out, log out
    return redirect('/') # regardless just go home
# A blank newline for nicer look
@app.route('/upload', methods=['GET', 'POST']) # The page for `http(s)://this_site/upload`
def upload(): # The arguments are handled using the POST method so no arguments here
    if not is_authenticated(): # If you're not logged in
        flash("Please log in to upload pictures.") # Tell'em
        return redirect('/login') # Go to login maaan
    # A blank newline for nicer look
    if request.method == 'POST': # If the method is POST (meaning you submitted the form)
        file = request.files['file'] # Gets the uploaded file
        if not file: # If no file
            flash('No file selected') # Tell'em
            return redirect('/upload') # Go back
        if not file.filename: # If the filename is empty
            flash('Invalid file') # Tell'em
            return redirect('/upload') # Go back
        if "/" in file.filename or "\\" in file.filename or ".." in file.filename: # If the filename is trying to do path traversal
            flash('Invalid file') # Tell'em
            return redirect('/upload') # Go back
        # A blank newline for nicer look
        uploader = current_username() # We separate files by uploader
        user_dir = os.path.join(UPLOAD_FOLDER, uploader)  # their personal corner
        os.makedirs(user_dir, exist_ok=True) # Make sure their corner exists
        # temp dir for this upload to isolate everything
        temp_extract = os.path.join(user_dir, f"tmp_{uuid.uuid4().hex[:12]}") # A temp dir for this upload to isolate everything
        os.makedirs(temp_extract, exist_ok=True) # come on we gotta make sure the temp dir have a space to spawn
        # A blank newline for nicer look
        try: # So errors won't crash the server
            data = file.stream.read() # read the file data to avoid duplicate reads
            filename = file.filename.lower() # lowercase the filename for easier checks
            if not (b"PNG" in data and b"IHDR" in data and b"IDAT" in data and b"IEND" in data): # If it doesn't have proper PNG format
                raise ValueError("Invalid file") # exits and call cleanup by raising error
            if filename.endswith(('.png', '.apng')): # If the image is a png
                with open(os.path.join(user_dir, file.filename), "wb") as f: # Save the image into their corner
                    f.write(data) # Write the data
                flash('Image uploaded!') # Tell'em
                return redirect('/') # Go home
            if not is_admin(): # non-admin stops here
                flash('Invalid file') # Tell'em
                return redirect('/upload') # Go back
            if filename.endswith(('.tar', '.tar.gz', '.tgz')):  # Admins can also upload .tar/.tar.gz/.tgz/.zip for batch uploading community contents (.zip is down there)
                with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tar: # makes a temp tar
                    files = [] # Keep track of files
                    for child in tar.getnames(): # Check for path traversal for every file
                        if '..' in child or child.startswith('/'): # if they are naughty
                            raise ValueError("Invalid file") # raise error and also fire whoever that admin is
                        target_path = os.path.abspath(os.path.join(temp_extract, child)) # Lets see where it actually lands at
                        if not target_path.startswith(os.path.abspath(temp_extract) + os.sep): # Aw man he did path traversal somehow, thats not normal
                            raise ValueError("Invalid file") # raise error and we seriously need to check which admin does this and do a full investigation
                        files.append(target_path) # Otherwise its very fine and we keep track of it for later use
                    tar.extractall(path=temp_extract) # Extract to temp dir
                        # if it's a file, check png if it looks like one
                for item in os.listdir(temp_extract): # move the files to where they belongs
                    src = os.path.join(temp_extract, item) # find where it is at
                    dst = os.path.join(user_dir, item) # find where they are supposed to be at
                    if os.path.exists(dst): # if have alr existing file with same name
                        if os.path.isfile(dst): # if its a file
                            os.remove(dst) # overwrite it
                        else: # if its a dir
                            shutil.rmtree(dst, ignore_errors=True) # remove the dir
                    shutil.move(src, dst) # move the files to where they belongs
                # A blank newline for nicer look
                flash('Batch images uploaded!') # Tell'em
                return redirect('/') # Go back
            elif filename.endswith('.zip'): # ok this is the zip part
                with zipfile.ZipFile(io.BytesIO(data), 'r') as z: # makes a temp zip
                    for zi in z.infolist(): # Check for path traversal for every file
                        if zi.is_dir(): # if its a dir
                            continue  # skip it for simplicity
                        if '..' in zi.filename or zi.filename.startswith('/'): # if they are naughty
                            raise ValueError("Invalid file") # raise error and also fire whoever that admin is (again)
                        target_path = os.path.abspath(os.path.join(temp_extract, zi.filename)) # Lets see where it actually lands at
                        if not target_path.startswith(os.path.abspath(temp_extract) + os.sep): # Aw man he did path traversal somehow, thats not normal
                            raise ValueError("Invalid file") # raise error and we seriously need to check which admin does this and do a full investigation
                        z.extract(zi, temp_extract) # Extract to temp dir
                # move like above
                for item in os.listdir(temp_extract): # I know I should add comments too but
                    src = os.path.join(temp_extract, item) # This is literally the same
                    dst = os.path.join(user_dir, item) # as the one above so
                    if os.path.exists(dst): # Please refer to the comments above
                        if os.path.isfile(dst): # Im not even copying
                            os.remove(dst) # and pasting
                        else: # here cuz
                            shutil.rmtree(dst, ignore_errors=True) # Im lazy
                    shutil.move(src, dst) # thx
                # A blank newline for nicer look
                flash('Batch images uploaded!') # Tell'em
                return redirect('/') # Go back
            flash('Invalid file') # if we reach here, an admin uploaded an unsupported file, tell'em
            return redirect('/upload') # Go back
        except Exception as e: # Oh no theres an error
            flash(f'Upload failed: {str(e)}') # damn it
            return redirect('/upload') # go back
        finally: # Anyways the operation is either completed or aborted
            shutil.rmtree(temp_extract, ignore_errors=True)  # either way we can delete temp
    # A blank newline for nicer look
    content = """
    <div class="card">
        <h2>Upload picture</h2>
        <p>Upload Images to the Gallery and share your moments!</p>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept=".png,.apng,.tar,.tar.gz,.tgz,.zip" required>
            <!--not even going dynamically adjust accepted formats cuz me lazy :p-->
            <br><br>
            <button type="submit">Upload</button>
        </form>
    </div>
    """ # The form
    return render_template_string(BASE_TEMPLATE, content=content, current_username=current_username(), is_admin=True) # Renders the page
# A blank newline for nicer look
@app.route('/report/<path:batch>', methods=['POST']) # The page for `http(s)://this_site/report/a_path`
def report(batch): # We take arguments now which is what to report of
    global report_id, last_report_time # We need these so we can tell me health check bot someone is manually checking this for us (with a side effect of an extra workload to me)
    report_id += 1 # new report new report id
    last_report_time = time.time() # We reported now, update the time please
    batch = batch.split("/", 1) # split the path to later get reporter and reported file
    if len(batch) == 1: # if theres no /
        flash('Invalid report') # its not a normal report
        return redirect('/') # Go home
    data = { # What we put in the report
        "reporter": current_username() or "anonymous", # whoever reported this, might as well require them to log in so we know who did it but rn anonymous can report too
        "report_id": uuid.uuid6().hex, # an ID, what it does just go look it up above
        "message": f"reported abuse at {batch[1]} by {batch[0]}", # What did whoever report
        "timestamp": int(time.time()) # When did they report
    } # I really dont want to comment what this bracket does anymore
    path = os.path.join(REPORT_FOLDER, f"{report_id}.json") # Where is the report file
    with open(path, 'w') as f: # Lets write to that file
        json.dump(data, f, indent=2) # woo we wrote it into the file
    # What? you say the report failed here before the bot catches? let it burn even if the bot caught it we still gotta let it burn until we shut the server off innit.. oh wait maybe I should make the bot dynamic too so I can hotfix it. TODO TODO TODO TODO TODO TODO TODO
    flash('Report submitted - thank you!') # Tell'em
    return redirect('/') # Go home
# A blank newline for nicer look
@app.route(f'/{REPORT_FOLDER}/<int:rid>.json') # The page for `http(s)://this_site/reports/report_filename`
def get_report(rid): # we takes in the report id
    path = os.path.join(REPORT_FOLDER, f"{rid}.json") # We just do it in that format to force them query int.json only so we ensure they can't read any files that is not a report 
    if not os.path.exists(path): # If there is no such report
        abort(404) # 404'em
    if not os.path.abspath(path).startswith(os.path.abspath(REPORT_FOLDER)): # If they are trying to path traverse
        abort(403) # 403'em
    return send_file(path) # give them the report
# A blank newline for nicer look
@app.route(f'/{UPLOAD_FOLDER}/<path:p>') # The page for `http(s)://this_site/uploads/filename`
def uploaded_file(p): # We take in which file they want
    if "png" not in p.rsplit(".", 1)[1].lower(): # If its not png (or apng)
        abort(404) # We die (jk we just 404'em)
        # The reason why we 404 non-png is because this is intended to only be used for index page to query the images for the <img>s and so they can't use this endpoint to read the hidden flag inside /uploads
    path = os.path.join(UPLOAD_FOLDER, p) # the actual path of the image
    if not os.path.exists(path): # If there is no such file
        abort(404) # 404'em
    if not os.path.abspath(path).startswith(os.path.abspath(UPLOAD_FOLDER)): # If they are trying to path traverse
        abort(403) # 403'em
    return send_file(path) # give them the image
# A blank newline for nicer look
if __name__ == '__main__': # so it will only run when directly executed, but what kind of wrong-minded would import this file bruh
    app.run(host='0.0.0.0', port=5000) # runs the server, lol
# A blank newline for nicer look
# wait did my boss just said someone will take over my place
# oh wait oh no I'm def getting fired after this one