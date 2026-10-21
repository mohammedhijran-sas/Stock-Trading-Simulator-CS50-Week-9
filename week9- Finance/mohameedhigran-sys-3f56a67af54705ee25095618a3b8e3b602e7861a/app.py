import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)

        # Ensure passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username does not already exist
        if len(rows) != 0:
            return apology("username already exist", 400)

        # Hash the user's password
        hash_password = generate_password_hash(request.form.get("password"))

        # Insert the new user into database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hash_password)

        # Log user in
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        session["user_id"]
    )

    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = user_cash[0]["cash"]

    total_value = cash
    portfolio = []

    for stock in stocks:
        item = lookup(stock["symbol"])
        if item:
            current_price = item["price"]
            total_stock_value = current_price * stock["total_shares"]
            total_value += total_stock_value
            portfolio.append({
                "symbol": stock["symbol"],
                "name": item["name"],
                "shares": stock["total_shares"],
                "price": current_price,
                "total": total_stock_value
            })

    return render_template("index.html", portfolio=portfolio, cash=cash, total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)

        item = lookup(symbol.upper())
        if not item:
            return apology("invalid symbol", 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be a positive integer", 400)
        except ValueError:
            return apology("shares must be an integer", 400)

        # Check user cash
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = user_cash[0]["cash"]

        total_cost = item["price"] * shares

        if cash < total_cost:
            return apology("can't afford", 400)

        # Update database (cash, and add transaction)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", total_cost, session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], item["symbol"], shares, item["price"])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
        session["user_id"]
    )
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("must provide symbol", 400)

        item = lookup(symbol)
        if item is None:
            return apology("invalid symbol", 400)

        return render_template("quoted.html", item=item)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must provide password confirmation", 400)
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(rows) != 0:
            return apology("username already exist", 400)

        hash_password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hash_password)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    stocks = db.execute(
        "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0",
        session["user_id"]
    )

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("must provide symbol", 400)

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be a positive integer", 400)
        except ValueError:
            return apology("shares must be an integer", 400)

        user_shares = db.execute(
            "SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"], symbol
        )

        if not user_shares or user_shares[0]["total_shares"] < shares:
            return apology("you do not own that many shares", 400)

        item = lookup(symbol)
        if not item:
            return apology("invalid symbol", 400)

        total_sale = item["price"] * shares

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", total_sale, session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                   session["user_id"], symbol, -shares, item["price"])

        return redirect("/")
    else:
        return render_template("sell.html", stocks=stocks)
