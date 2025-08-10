# Add these debug endpoints to help troubleshoot the configuration

@bp.route("/lti/debug/config", methods=["GET"])
def debug_config():
    """Debug endpoint to show tool configuration."""
    from flask import url_for
    
    config = {
        "login_url": url_for("lti.login", _external=True),
        "launch_url": url_for("lti.lti_launch", _external=True),
        "deep_link_url": url_for("lti.deep_link", _external=True),
        "jwks_url": url_for("jwks.jwks", _external=True) if "jwks.jwks" in current_app.view_functions else "NOT_CONFIGURED",
        "base_url": request.host_url,
        "registered_platforms": []
    }
    
    # Add platform information if available
    try:
        platforms = Platform.query.all()
        for platform in platforms:
            config["registered_platforms"].append({
                "issuer": platform.issuer,
                "client_id": platform.client_id,
                "auth_login_url": platform.auth_login_url,
                "jwks_uri": platform.jwks_uri
            })
    except Exception as e:
        config["platform_error"] = str(e)
    
    return jsonify(config)

@bp.route("/lti/debug/test-login", methods=["GET", "POST"])
def debug_test_login():
    """Test endpoint to simulate a login request."""
    if request.method == "GET":
        # Show a form to test login manually
        return f"""
        <html>
        <body>
        <h2>Test LTI Login</h2>
        <form method="POST" action="{url_for('lti.login')}">
            <p>iss (Platform Issuer): <input name="iss" value="https://your-moodle-site.com" style="width: 300px;"></p>
            <p>target_link_uri: <input name="target_link_uri" value="{url_for('lti.lti_launch', _external=True)}" style="width: 300px;"></p>
            <p>client_id: <input name="client_id" value="your-client-id" style="width: 300px;"></p>
            <p>login_hint: <input name="login_hint" value="test-user" style="width: 300px;"></p>
            <p><input type="submit" value="Test Login"></p>
        </form>
        </body>
        </html>
        """
    else:
        return redirect(url_for('lti.login'), code=307)  # Forward POST data
