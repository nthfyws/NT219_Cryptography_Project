def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    from datetime import datetime
    if isinstance(value, datetime):
        return value.strftime(format)
    try:
        dt = datetime.fromisoformat(str(value))
        return dt.strftime(format)
    except Exception:
        return value

# Trong app.py thêm: