# importing twilio
from twilio.rest import Client
  
# Your Account Sid and Auth Token from twilio.com / console

def sendotp(number):
    account_sid = 'AC4b097493ecb42f35f5b0d02e420aeed5'
    auth_token = 'bceaef1a0777ba782d22699ea1371cbf'
    
    client = Client(account_sid, auth_token)
    
    ''' Change the value of 'from' with the number 
    received from Twilio and the value of 'to'
    with the number in which you want to send message.'''
    message = client.messages.create(
                                from_='+12183074015',
                                body ='body',
                                to = number
                            )

sendotp('+6598994217')
