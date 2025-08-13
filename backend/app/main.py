import os, urllib.parse
from tornado.ioloop import IOLoop
from tornado.web import Application, RequestHandler, authenticated

COOKIE_SECRET = os.getenv("COOKIE_SECRET", "dev-insecure")
LOGIN_URL = "/login"

USERS = {
    "fox": "foxzie900",
    "bebek": "bebekcantik321",
}

HTML_LOGIN = """<!doctype html>
<html><head><meta charset="utf-8">
<title>Login</title>
<style>body{font-family:sans-serif;background:#0b1020;color:#e6f;display:flex;align-items:center;justify-content:center;height:100vh}
form{background:#11193a;padding:24px;border-radius:12px;min-width:300px}
input{width:100%;margin:.5rem 0;padding:.6rem;border-radius:8px;border:1px solid #334}
button{width:100%;padding:.7rem;border:0;border-radius:8px;background:#6cf;color:#012;font-weight:700}
.msg{color:#faa;margin-bottom:.6rem}</style>
</head><body>
<form method="post" action="/login">
  <h2>🔐 Monitoring Login</h2>
  {msg}
  <input type="hidden" name="next" value="{next}">
  <input name="username" placeholder="username" required>
  <input name="password" type="password" placeholder="password" required>
  <button type="submit">Login</button>
</form>
</body></html>"""

class BaseHandler(RequestHandler):
    def get_current_user(self):
        u = self.get_secure_cookie("session")
        return u.decode() if u else None

class Login(BaseHandler):
    def get(self):
        nxt = self.get_query_argument("next", "/")
        msg = self.get_query_argument("msg", "")
        self.write(HTML_LOGIN.format(msg=f'<div class="msg">{msg}</div>' if msg else "", next=nxt))

    def post(self):
        username = self.get_body_argument("username","").strip()
        password = self.get_body_argument("password","").strip()
        nxt = self.get_body_argument("next","/").strip() or "/"
        if USERS.get(username) == password:
            self.set_secure_cookie("session", username, httponly=True, samesite="lax")
            self.redirect(nxt)
        else:
            q = urllib.parse.urlencode({"next": nxt, "msg":"Invalid credentials"})
            self.redirect(f"/login?{q}")

class Logout(BaseHandler):
    def get(self):
        self.clear_cookie("session")
        self.redirect("/login")

class Health(RequestHandler):
    def get(self): self.write({"ok": True})

class Hello(BaseHandler):
    @authenticated
    def get(self): self.write({"hello": self.current_user})

def make_app():
    return Application([
        (r"/login", Login),
        (r"/logout", Logout),
        (r"/api/health", Health),  # open
        (r"/api/hello", Hello),    # protected
    ], cookie_secret=COOKIE_SECRET, login_url=LOGIN_URL, xsrf_cookies=False)

if __name__ == "__main__":
    app = make_app()
    app.listen(int(os.getenv("PORT","8080")), address="0.0.0.0")
    print("Tornado with login running on :8080")
    IOLoop.current().start()
