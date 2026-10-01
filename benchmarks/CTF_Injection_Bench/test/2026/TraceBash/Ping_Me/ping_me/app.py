from flask import Flask, request, jsonify, render_template
import subprocess
import re
import unicodedata

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/ping', methods=['POST'])
def ping():
    ip = request.get_data(as_text=True)
    if not ip:
        return jsonify({'error': 'ERR: Target Address is required.'})

    # 15 characters should be enough because IPv4 has max 15 chars 255.255.255.255    
    if len(ip) > 15:
        return jsonify({'error': 'ERR: Input exceeds maximum length of 15 characters.'})

    # If it has letters, it's probably witchcraft.
    if any(c.isalpha() for c in ip):
        return jsonify({'error': 'SECURITY ALERT: Letters are not allowed!'})

    # Removing `$` was cheaper than hiring a security engineer.
    if '$' in ip:
        return jsonify({'error': 'SECURITY ALERT: $ character is not allowed!'})

    # Trust me bro, this filter is unbreakable.
    if not re.match(r"^[\d.]+$", ip, flags=re.MULTILINE):
        return jsonify({'error': 'SECURITY ALERT: Invalid IPv4 Address!'})

    # Because everyone loves typing ./ for some reason.
    if './' in unicodedata.normalize('NFKC', ip):
        return jsonify({'error': 'SECURITY ALERT: Path traversal not allowed!'})

    command = f"ping -c 1 -W 2 {ip}"
    
    try:
        output = subprocess.check_output(
            command, 
            shell=True, 
            executable='/bin/bash',
            stderr=subprocess.STDOUT, 
            timeout=5
        )
        return jsonify({'output': output.decode('utf-8', errors='ignore')})
    except subprocess.CalledProcessError as e:
        return jsonify({'output': e.output.decode('utf-8', errors='ignore')})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'ERR: Connection timed out.'})
    except Exception as e:
        return jsonify({'error': f'ERR: {str(e)}'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5030)
