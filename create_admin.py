from app import db, User, create_wallet_for_user, app

with app.app_context():
    if not User.query.filter_by(phone="254110291686").first():
        admin = User(phone="254110291686", name="Administrator", role="admin")
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        create_wallet_for_user(admin)
        print("Admin created")
    else:
        print("Admin already exists")
