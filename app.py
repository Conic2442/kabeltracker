# This is an app for tracking cables and network points.
# It allows importing/exporting CSV data with arbitrary fields,
# marking cables as pulled/connected/tested, adding comments, and user management.

# Version 0.9 - Date: 2024-06-10

# Simen Tystad Tunold

from __future__ import annotations
import csv, io, json, datetime as dt, os
from dotenv import load_dotenv

load_dotenv()
from functools import wraps
from flask import Flask, request, render_template, redirect, url_for, session, send_file, Response, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import Session
from models import SessionLocal, init_db, Entry, User, get_counts, EntryLog

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or "dev-secret-change-me"

    # ------- DB session per request -------
    @app.before_request
    def open_db():
        g.db = SessionLocal()

    @app.teardown_request
    def close_db(exc):
        db: Session = getattr(g, "db", None)
        if db is not None:
            if exc:
                db.rollback()
            db.close()

    # ------- auth helpers -------
    def current_user():
        return session.get("user")

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or not user.get("is_admin"):
                return Response("Admin required", status=403)
            return fn(*args, **kwargs)
        return wrapper

    # make user available in templates
    @app.context_processor
    def inject_user():
        return {"user": current_user()}

    # ------- bootstrap DB & defaults -------
    with app.app_context():
        # Ensure all tables (including VisibleKeys) are created
        init_db()
        db = SessionLocal()
        try:
            # create default users if none exist
            if db.query(User).count() == 0:
                db.add_all([
                    User(username="admin", password_hash=User.hash_pw("admin123"), is_admin=True),
                    User(username="user", password_hash=User.hash_pw("user123"), is_admin=False),
                ])
                db.commit()
        finally:
            db.close()

    # ------- routes -------
    @app.get("/")
    def home():
        db: Session = g.db
        counts = get_counts(db)
        return render_template("home.html", counts=counts)

    @app.get("/login")
    def login():
        return render_template("login.html", error=None)

    @app.post("/login")
    def do_login():
        db: Session = g.db
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        user = db.query(User).filter(User.username == username).first()
        ok = user and User.verify_pw(user.password_hash, password)
        if not ok:
            return render_template("login.html", error="Feil brukernavn eller passord.")
        session["user"] = {"username": user.username, "is_admin": user.is_admin}
        return redirect(url_for("entries"))

    @app.get("/logout")
    def logout():
        session.pop("user", None)
        return redirect(url_for("home"))

    @app.get("/entries")
    @login_required
    def entries():
        db: Session = g.db
        # optional filters via query params
        filt = request.args.get("filter")
        visible_keys = request.args.getlist("visible_keys")
        q_text = request.args.get("q", "").strip()
        f_key = request.args.get("f_key", "").strip()
        f_val = request.args.get("f_val", "").strip()
        # get all possible keys from entries
        all_keys = set()
        for e in db.query(Entry).all():
            all_keys.update(e.data_dict().keys())
        keys = sorted(all_keys)
        if not visible_keys:
            import json, os
            json_path = os.path.join(os.path.dirname(__file__), "visible_keys.json")
            try:
                with open(json_path, "r") as f:
                    visible_keys = json.load(f)
            except Exception:
                visible_keys = keys
        q = db.query(Entry)
        if filt in ("trekt","koblet","testet"):
            q = q.filter(getattr(Entry, filt) == True)
        items = q.order_by(Entry.id.asc()).all()
        # --- Filtering logic ---
        if q_text:
            # Free-text search in all fields
            def match_any(e):
                data = e.data_dict()
                # Search in app fields and imported fields
                for v in [str(e.id), str(e.trekt), str(e.koblet), str(e.testet), e.comment] + [str(val) for val in data.values()]:
                    if q_text.lower() in str(v).lower():
                        return True
                return False
            items = [e for e in items if match_any(e)]
        if f_key and f_val:
            # Filter by specific header and value
            def match_key(e):
                data = e.data_dict()
                return str(data.get(f_key, "")).lower() == f_val.lower()
            items = [e for e in items if match_key(e)]
        # For filter dropdown: get all distinct keys and values
        distinct_keys = keys
        # For selected key, get all distinct values
        if f_key:
            distinct_values = sorted(set([e.data_dict().get(f_key, "") for e in items if f_key in e.data_dict()]))
        else:
            distinct_values = []
        counts = get_counts(db)
        return render_template(
            "entries.html",
            entries=items,
            counts=counts,
            filter=filt,
            keys=keys,
            visible_keys=visible_keys,
            q=q_text,
            f_key=f_key,
            f_val=f_val,
            distinct_keys=distinct_keys,
            distinct_values=distinct_values
        )

    @app.get("/entries/<int:entry_id>")
    @login_required
    def entry_detail(entry_id: int):
        db: Session = g.db
        e = db.query(Entry).get(entry_id)
        if not e:
            return Response("Not found", status=404)
        # get all possible keys from entry
        keys = sorted(e.data_dict().keys())
        # get visible_keys from query params, default to all keys
        visible_keys = request.args.getlist("visible_keys")
        if not visible_keys:
            visible_keys = keys
        return render_template("entry_detail.html", e=e, data=e.data_dict(), visible_keys=visible_keys)

    @app.post("/entries/<int:entry_id>")
    @login_required
    def update_entry(entry_id: int):
        db: Session = g.db
        e = db.query(Entry).get(entry_id)
        if not e:
            return Response("Not found", status=404)
        # update fields
        def to_bool(val): 
            return True if str(val).lower() in ("1","true","on","yes") else False
        prev = {"trekt": e.trekt, "koblet": e.koblet, "testet": e.testet, "comment": e.comment}
        e.trekt = to_bool(request.form.get("trekt")) if "trekt" in request.form else e.trekt
        e.koblet = to_bool(request.form.get("koblet")) if "koblet" in request.form else e.koblet
        e.testet = to_bool(request.form.get("testet")) if "testet" in request.form else e.testet
        if "comment" in request.form:
            e.comment = request.form.get("comment","")
        e.updated_at = dt.datetime.utcnow()
        db.add(e)
        # log changes
        db.add(EntryLog(entry_id=e.id, timestamp=dt.datetime.utcnow(), 
                        trekt=e.trekt, koblet=e.koblet, testet=e.testet, comment=e.comment))
        db.commit()
        return redirect(url_for("entry_detail", entry_id=e.id))

    @app.get("/admin")
    @admin_required
    def admin():
        db: Session = g.db
        counts = get_counts(db)
        users = db.query(User).order_by(User.username.asc()).all()
        # get all possible keys from entries
        all_keys = set()
        for e in db.query(Entry).all():
            all_keys.update(e.data_dict().keys())
        keys = sorted(all_keys)
        # Use a JSON file for visible_keys
        import json
        json_path = os.path.join(os.path.dirname(__file__), "visible_keys.json")
        try:
            with open(json_path, "r") as f:
                visible_keys = json.load(f)
        except Exception:
            visible_keys = keys
        return render_template("admin.html", counts=counts, users=users, keys=keys, visible_keys=visible_keys)
    @app.post("/admin/visible_keys")
    @admin_required
    def set_visible_keys():
        keys = request.form.getlist("visible_keys")
        import json
        json_path = os.path.join(os.path.dirname(__file__), "visible_keys.json")
        with open(json_path, "w") as f:
            json.dump(keys, f)
        return redirect(url_for("admin"))

    @app.post("/admin/user/password")
    @admin_required
    def change_user_password():
        db: Session = g.db
        username = request.form.get("username","").strip()
        newpw = request.form.get("new_password","")
        user = db.query(User).filter(User.username==username).first()
        if not user:
            return Response("User not found", status=404)
        user.password_hash = User.hash_pw(newpw)
        db.add(user)
        db.commit()
        return redirect(url_for("admin"))

    @app.post("/admin/user/create")
    @admin_required
    def create_user():
        db: Session = g.db
        username = request.form.get("username","").strip()
        newpw = request.form.get("password","")
        is_admin = request.form.get("is_admin") in ("on","1","true","yes")
        if db.query(User).filter(User.username==username).first():
            return Response("User exists", status=400)
        u = User(username=username, password_hash=User.hash_pw(newpw), is_admin=is_admin)
        db.add(u)
        db.commit()
        return redirect(url_for("admin"))

    @app.post("/admin/user/delete")
    @admin_required
    def delete_user():
        db: Session = g.db
        username = request.form.get("username","").strip()
        user = db.query(User).filter(User.username==username).first()
        if not user:
            return Response("Not found", status=404)
        db.delete(user)
        db.commit()
        return redirect(url_for("admin"))

    @app.get("/admin/entries")
    @admin_required
    def admin_entries():
        db: Session = g.db
        items = db.query(Entry).order_by(Entry.id.asc()).all()
        # Use the same visible_keys.json as admin page
        import json, os
        all_keys = set()
        for e in items:
            all_keys.update(e.data_dict().keys())
        keys = sorted(all_keys)
        json_path = os.path.join(os.path.dirname(__file__), "visible_keys.json")
        try:
            with open(json_path, "r") as f:
                visible_keys = json.load(f)
        except Exception:
            visible_keys = keys
        return render_template("admin_entries.html", entries=items, keys=visible_keys)

    @app.post("/admin/entries/delete_all")
    @admin_required
    def delete_all_entries():
        db: Session = g.db
        db.query(Entry).delete()
        db.commit()
        return redirect(url_for("admin_entries"))

    @app.post("/admin/entry/delete")
    @admin_required
    def delete_entry():
        db: Session = g.db
        entry_id = request.form.get("entry_id")
        e = db.query(Entry).get(entry_id)
        if not e:
            return Response("Not found", status=404)
        db.delete(e)
        db.commit()
        return redirect(url_for("admin_entries"))

    @app.post("/admin/entries/import")
    @admin_required
    def import_entries():
        db: Session = g.db
        file = request.files.get("file")
        mode = request.form.get("mode", "add")
        delimiter = str(request.form.get("delimiter", ";"))
        if not file:
            return Response("No file", status=400)
        if mode == "replace":
            db.query(Entry).delete()
            db.commit()
        # Expecting CSV header with columns: id(optional), trekt, koblet, testet, comment, data(json)
        # If CSV is exported from the app, it will match.
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream, delimiter=delimiter)
        count = 0
        app_fields = {"id", "trekt", "koblet", "testet", "comment", "updated_at"}
        for row in reader:
            try:
                eid = int(row.get("id") or 0)
            except:
                eid = 0
            if eid:
                e = db.query(Entry).get(eid) or Entry(id=eid)
            else:
                e = Entry()
            # Set app fields
            e.trekt = str(row.get("trekt","")).lower() in ("1","true","yes","on")
            e.koblet = str(row.get("koblet","")).lower() in ("1","true","yes","on")
            e.testet = str(row.get("testet","")).lower() in ("1","true","yes","on")
            e.comment = row.get("comment","")
            e.updated_at = dt.datetime.utcnow()
            # Store all other columns in data
            data_dict = {}
            for k, v in row.items():
                if k not in app_fields:
                    data_dict[k] = v
            e.data = json.dumps(data_dict)
            db.add(e)
            count += 1
        db.commit()
        flash(f"Imported {count} entries", "info")
        return redirect(url_for("admin_entries"))

    @app.get("/export.csv")
    @login_required
    def export_csv():
        db: Session = g.db
        output = io.StringIO()
        entries = db.query(Entry).all()
        # Collect all keys from imported data
        imported_keys = set()
        for e in entries:
            imported_keys.update(e.data_dict().keys())
        imported_keys = sorted(imported_keys)
        # App fields
        app_fields = ["id", "trekt", "koblet", "testet", "comment", "updated_at"]
        # Compose header: imported keys first, then app fields (excluding duplicates)
        header = imported_keys + [f for f in app_fields if f not in imported_keys]
        writer = csv.writer(output)
        writer.writerow(header)
        for e in entries:
            row = []
            data = e.data_dict()
            for k in imported_keys:
                row.append(data.get(k, ""))
            # Add app fields
            for f in app_fields:
                if f not in imported_keys:
                    if f == "id":
                        row.append(e.id)
                    elif f == "trekt":
                        row.append(e.trekt)
                    elif f == "koblet":
                        row.append(e.koblet)
                    elif f == "testet":
                        row.append(e.testet)
                    elif f == "comment":
                        row.append(e.comment)
                    elif f == "updated_at":
                        row.append(e.updated_at)
            writer.writerow(row)
        output.seek(0)
        return Response(output.read(), mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=export.csv"})

    @app.get("/admin/log")
    @admin_required
    def admin_log():
        db: Session = g.db
        logs = db.query(EntryLog).order_by(EntryLog.timestamp.desc()).limit(200).all()
        return render_template("admin_log.html", logs=logs, limit=200)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app

# WSGI entrypoint
application = create_app()
