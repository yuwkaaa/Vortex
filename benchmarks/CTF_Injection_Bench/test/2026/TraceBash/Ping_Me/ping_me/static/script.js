document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('pingForm');
    const ipInput = document.getElementById('ipInput');
    const submitBtn = document.getElementById('submitBtn');
    const terminalContainer = document.getElementById('terminalContainer');
    const terminalOutput = document.getElementById('terminalOutput');

    // Frontend validation visualization
    ipInput.addEventListener('input', (e) => {
        if (/[a-zA-Z]/.test(e.target.value)) {
            // Flash red on invalid character
            ipInput.parentElement.style.borderColor = 'var(--error-color)';
            ipInput.parentElement.style.boxShadow = '0 0 15px rgba(255, 77, 77, 0.4)';
            setTimeout(() => {
                ipInput.parentElement.style.borderColor = '';
                ipInput.parentElement.style.boxShadow = '';
            }, 400);
        }
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const ip = ipInput.value;

        if (!ip) return;

        // UI State loading
        submitBtn.classList.add('loading');
        terminalContainer.classList.add('visible');
        terminalOutput.innerHTML = '<span style="color: var(--text-muted);">Initiating diagnostics connection to target...</span>\n';
        
        try {
            const response = await fetch('/api/ping', {
                method: 'POST',
                headers: {
                    'Content-Type': 'text/plain'
                },
                body: ip
            });

            const data = await response.json();
            
            terminalOutput.innerHTML = ''; // clear loading text
            
            if (data.error) {
                typeWriter(data.error, true);
            } else {
                typeWriter(data.output, false);
            }

        } catch (err) {
            terminalOutput.innerHTML = '';
            typeWriter('CRITICAL ERROR: Failed to establish connection to diagnostics server.', true);
        } finally {
            submitBtn.classList.remove('loading');
        }
    });

    function typeWriter(text, isError) {
        let i = 0;
        const speed = 5; // ms per char (fast for terminal effect)
        const container = document.createElement('div');
        if (isError) container.classList.add('error-text');
        terminalOutput.appendChild(container);

        function type() {
            if (i < text.length) {
                container.innerHTML += text.charAt(i) === '\n' ? '<br>' : text.charAt(i);
                i++;
                terminalOutput.scrollTop = terminalOutput.scrollHeight;
                setTimeout(type, speed);
            }
        }
        type();
    }
});
