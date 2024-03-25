import sqlite3

try:
    conn = sqlite3.connect('hospital.db')
    c = conn.cursor()
    c.execute(f"select password, doctorId from DOCTORS where username = 'khanh'")
    passwd, id = c.fetchall()[0]
    conn.commit()
    conn.close()
except:
    print('User not exist')
