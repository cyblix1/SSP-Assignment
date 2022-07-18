import datetime
 
def timer():
    today = datetime.date.today()

    expire = 31
    day = today.strftime(' %d ')
    daysLeft = (expire - day)

    print (today.strftime('you have '+ str(daysLeft) +' days to change your password'))