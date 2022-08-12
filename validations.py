import re
#input validations
class Validations:
    #using regex
    def validate_password(password):
        reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,20}$"
        # compiling regex
        pat = re.compile(reg)
        # searching regex                 
        mat = re.search(pat, password)
        # validating conditions
        if mat:
            return False
        else:
            #password meets requirements
            return True
    #validate email
    def validate_email(email):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if(re.fullmatch(regex, email)):
            return True
        else:
            return False
    #validate security answer
    def validate_answer(answer):
            regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')

            if(regex.search(answer) == None):
                return True
            else:
                return False
                print("illegal characters in answer.") 