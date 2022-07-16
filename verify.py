import random
import smtplib
from configparser import ConfigParser

#configuration files
file = 'config.properties'
config = ConfigParser()
config.read(file)

my_email = config['email']['mail']
my_password = config['email']['password']

#to generate OTP is generateOTP()
class email_verification:
    def generateOTP(otp_size = 6):
        final_otp = ''
        for i in range(otp_size):
            final_otp = final_otp + str(random.randint(0,9))
        return final_otp
    
    def send_otp(final_otp,email):
        otp = final_otp + " is your otp"
        verfication_message = otp
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()
        s.login(my_email, my_password)
        s.sendmail('&&&&&&&&&&&',email,verfication_message)

    def verify_otp(otp_to_check, final_otp):
        if int(otp_to_check) == int(final_otp):
            #OTPS are same, therefore user is valid 
            return True
        else:
            return False    

#testing
email = "nattzwc@gmail.com"
otp = email_verification.generateOTP()
email_verification.send_otp(otp,email)
new_otp= input("ENter otp: ")
verify = email_verification.verify_otp(new_otp,otp)
if verify == True:
    print("correct")
else:
    print("wrong")
