#!/usr/bin/env python3
"""
HTTP/Web Honeypot - WordPress Admin Login Simulator
"""

import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request
from datetime import datetime

# Logging Format
logging_format = logging.Formatter('%(asctime)s %(message)s')

# HTTP Logger
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=50000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)
funnel_logger.propagate = False

def web_honeypot(input_username="admin", input_password="password"):
    """Create Flask app for web honeypot"""
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        """Main login page"""
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin')
    def wp_admin():
        """Alternative WordPress admin URL"""
        return render_template('wp-admin.html')
    
    @app.route('/admin')
    def admin():
        """Alternative admin URL"""
        return render_template('wp-admin.html')
    
    @app.route('/login')
    def login_page():
        """Alternative login URL"""
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        """Handle login attempts"""
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Log the attempt with timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_msg = f'{timestamp} {ip_address} attempted login - Username: {username}, Password: {password}, User-Agent: {user_agent}'
        funnel_logger.info(log_msg)
        
        # Force flush to disk
        for handler in funnel_logger.handlers:
            handler.flush()
        
        # Console output
        print(f"[HTTP LOGIN] {ip_address} - User: {username}, Pass: {password}")
        
        # Check credentials
        if username == input_username and password == input_password:
            print(f"[+] {ip_address} - Successful login!")
            return render_template('success.html', username=username)
        else:
            print(f"[-] {ip_address} - Failed login attempt")
            
            # Check for common attack patterns
            if any(pattern in username.lower() or pattern in password.lower() 
                   for pattern in ["'", '"', "or", "union", "select", "<script", "../../"]):
                alert_msg = f"[ALERT] {ip_address} - Possible injection attempt: User={username}, Pass={password}"
                print(alert_msg)
                funnel_logger.info(alert_msg)
            
            return render_template('failed.html')
    
    @app.route('/robots.txt')
    def robots():
        """Fake robots.txt to attract bots"""
        return """User-agent: *
Disallow: /admin/
Disallow: /wp-admin/
Disallow: /backup/
Disallow: /config/
Disallow: /database/
        """, 200, {'Content-Type': 'text/plain'}
    
    @app.route('/phpinfo.php')
    def phpinfo():
        """Fake phpinfo page"""
        log_msg = f"[ALERT] {request.remote_addr} accessed /phpinfo.php"
        print(log_msg)
        funnel_logger.info(log_msg)
        return "PHP Version 7.4.3 (phpinfo disabled for security)", 403
    
    @app.errorhandler(404)
    def page_not_found(e):
        """Log 404 attempts (directory brute-forcing detection)"""
        path = request.path
        ip = request.remote_addr
        log_msg = f"{ip} - 404 Not Found: {path}"
        funnel_logger.info(log_msg)
        print(f"[404] {log_msg}")
        return "404 Not Found", 404
    
    return app

def run_web_honeypot(port=5000, input_username="admin", input_password="password"):
    """Run the web honeypot"""
    print("\n" + "="*60)
    print("🌐 HTTP/WEB HONEYPOT")
    print("="*60)
    print(f"[*] Port: {port}")
    print(f"[*] Username: {input_username}")
    print(f"[*] Password: {input_password}")
    print(f"[*] URL: http://0.0.0.0:{port}")
    print(f"[*] Logs: http_audits.log")
    print(f"[*] Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    app = web_honeypot(input_username, input_password)
    
    try:
        # Run with threading to avoid blocking
        app.run(
            debug=False,  # Set to False in production
            port=port,
            host="0.0.0.0",
            threaded=True
        )
    except Exception as e:
        print(f"[!] Error starting web honeypot: {e}")
        raise

if __name__ == "__main__":
    """Standalone mode for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTP Honeypot')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port number')
    parser.add_argument('-u', '--username', default='admin', help='Username')
    parser.add_argument('-pw', '--password', default='password', help='Password')
    
    args = parser.parse_args()
    
    try:
        run_web_honeypot(port=args.port, input_username=args.username, input_password=args.password)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
