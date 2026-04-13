from flask import Flask, redirect, request

app = Flask(__name__)

@app.get('/bounce')
def bounce():
    return redirect(request.args.get('to', 'http://example.com'), code=302)

@app.get('/to-token-discovery')
def to_token_discovery():
    return redirect('http://token-service:5003/.well-known/mesh', code=302)

@app.get('/to-admin-a-health')
def to_admin_a_health():
    return redirect('http://internal-admin-a:5001/health', code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002)
