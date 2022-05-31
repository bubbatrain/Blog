'''

This app is a full Blog.

1. Each page include a header.html (with a dynamic navbar inside: when a user
is logged in, it does not show Login and Register button, only Log out) and
a footer.html (copyright, social media accounts)

2. In index.html every users can see all the posts that are stored in the
'Blogpost' table (title, subtitle, author, date, etc.). Admin can delete
posts from here.

3. Users, if they are already registered, can log in through a WTForm; app
will check if the email inserted is stored in the 'User' table and if the
hashed password is correct. If yes, user will be authorized and redirected
to homepage. If some error occurs during the process, flash messages will be
shown.

4. If a not-yet-user wants to register to the app, he can through a WTForm;
app will check if the email inserted will not already be in 'User' table and
will store the hashing of the password. If everything goes right, user will
be authorized and redirect to homepage. If some error occurs during the
process, flash messages will be shown.

5. When a user (authorized or not) clicks on a specific post, app will show
that specific post in post.html. Here, only authorized users can comments
the post through a WTForm with a CKEditor; each comment will be saved in
'Comments' table and they will be shown under the post (with a gravatar image
for each user).
Only admin can edit a post.

6. Authenticated users can logout at anytime with the button in navbar.

7. About and Contacts buttons in navbar are clickable by every user.

8. General info about app:
    - Database:
        3 tables ("User", "BlogPost", "Comments").
        Relationships:
            User - BlogPost: 1:N
            User - Comments: 1:N
            BlogPost - Comments: 1:N

    - Flask Login: custom decorator '@admin_only' in order to make sure that
    only admin can create, delete and edit posts.

    - WTForms: form classes are in forms.py and used through Jinja in
    templates


'''
import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from flask_wtf import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import *
from flask_gravatar import Gravatar
from functools import wraps


# Initial server configuration
app = Flask(__name__)
ckeditor = CKEditor(app)
Bootstrap(app)

# --------  Flask Login configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="/login"
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------  Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Creating tables in DB
# User is parent, BlogPost is child.
# There is a One to Many relationship between User and BlogPost: a User can
# many posts, but a specific post can be written by only a single user.
# This relationship means that tables are connected: modifying one also
# modifies the other
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    # This will act like a List of Comment objects attached to each User.
    # The "comment_author" refers to the author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "author.id" that refers to the tablename
    # of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    #Create reference to the User object, the "posts" refers to the
    # posts property in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # This will act like a List of Comment objects attached to each BlogPost.
    # The "parent_post" refers to the property in the Comment class.
    comments = relationship("Comment", back_populates="parent_post")

# Create Comment table. Relationship is One to Many between User and Comment.
# One User is linked to many Comment

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "author_id" that refers to the tablename
    # of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "comments" refers to the
    # comments property in the User class.
    comment_author = relationship("User", back_populates="comments")
    # Create Foreign Key, "parent" that refers to the tablename
    # of BlogPost.
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    # Create reference to the BlogPost object, the "comments" refers to the
    # comments property in the BlogPost class.
    parent_post = relationship("BlogPost", back_populates="comments")
    text =  db.Column(db.Text, nullable=False)

db.create_all()


# -------- Gravatar configuration
gravatar = Gravatar(app, size=100, rating='g', default='robohash', force_default=False, force_lower=False, use_ssl=False, base_url=None)


# ------- Flask Routes
# Custom Login Decorator. This decorator is used to prevent normal users
# to edit_post, make_post, and delete_post. Only Admin (id==1) can do these
# operations
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# Rendering homepage, showing all posts in the DB
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)

# Rendering register.html, where a user can register to the blog. His data
# will be stored in User table in DB
@app.route('/register', methods=["GET", "POST"])
def register():
    # Create WTForm
    form = RegisterForm()
    # Validate the user's entry when he hit submit
    if form.validate_on_submit():
        # Get hold of user data
        email = form.email.data
        password = form.password.data
        name = form.name.data
        # Check if email inserted by user is not already stored in DB,
        # using a query on DB
        if User.query.filter_by(email=email).first() == None:
            # User password is hashed
            hashed_password = generate_password_hash(password=password,
                                                   method='pbkdf2:sha256',
                                                   salt_length=8)
            # Create new record in DB
            new_user = User(name=name,
                              email=email,
                              password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate new user
            login_user(new_user)
            # After a new User is created, user get redirected to homepage
            return redirect(url_for("get_all_posts"))

        else:
            # If user insert an email that is already stored in the DB, show
            # an error through flash message in login.html
            flash("You have already signed up with that email. Please" \
                    " log in instead.")
    return render_template("register.html", form=form)

# Rendering login.html, where user can insert their credentials in a form.
@app.route('/login', methods=["POST", "GET"])
def login():
    # Create WTForm
    form = LoginForm()
    # Validate the user's entry when he hit submit
    if form.validate_on_submit():
        # Get hold of user data
        email = form.email.data
        password = form.password.data
        # Query on DB to get hold of current user
        user = User.query.filter_by(email=email).first()
        if user == None:
            # If user insert an email that is not in the DB, show
            # an error through flash message in login.html
            flash("That email is not correct, please try again.")
            return render_template("login.html", form=form)
        else:
            # Check if hashed password is equal to hashed password in DB
            if check_password_hash(user.password, password):
                # Login and authorized user
                login_user(user)
                # Redirect user to homepage
                return redirect(url_for("get_all_posts"))
            else:
                # If user insert incorrect credentials, show an error
                # through flash message in login.html
                flash("Invalid credentials, please try again.")
                return render_template("login.html", form=form)
    else:
        return render_template("login.html", form=form)



@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    # Query on DB to show post requested
    requested_post = BlogPost.query.get(post_id)
    # Query on DB to show all comments
    all_comments = Comment.query.all()
    # Create WTForm
    form = CommentForm()
    # Validate the user's entry when he hit submit
    if form.validate_on_submit():

        # Only registered (authenticated) users can post a comment
        if current_user.is_authenticated:
            # Get hold of user data
            comment = form.comment.data

            # Create new record in DB
            new_comment = Comment(author_id=current_user.id,
                                post_id=post_id,
                                text=comment,
                                parent_post=requested_post)


            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, form=form, comments=all_comments)

        # If user is not authenticated, redirect him to login.html and flash
        # a message
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form, comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

# Rendering new-post.html, only visible by admin
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)

# Rendering edit-post.html, only visible by admin
@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)

# Rendering delete-post.html, only visible by admin
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
