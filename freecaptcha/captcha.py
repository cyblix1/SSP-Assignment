import random
import os
from PIL import Image
import base64
from io import BytesIO

# Angles we'll rotate the original by
# when we create n rotations
def calculate_angles(n):
    return list(range(0, 360, 360 // n))

def rotate_img(img_path, angle):
    original_img  = Image.open(img_path)
    rotated = original_img.rotate(angle)
    buffered = BytesIO()
    rotated.save(buffered, format="PNG")
    b64_rot = base64.b64encode(buffered.getvalue())
    return b64_rot.decode("utf-8")

def captchafy(img_path, n=6):
    angles = calculate_angles(n)

    rotated_imgs = [
        {
            'original': False, 
            'image': rotate_img(img_path, angle)
        } for angle in angles]
    
    rotated_imgs[0]['original'] = True

    random.shuffle(rotated_imgs)

    correct_img = None
    for index, img in enumerate(rotated_imgs):
        if img['original']:
            correct_img = index

    return correct_img, [img['image'] for img in rotated_imgs]

def random_image(dir='images/'):
    dir_contents = os.listdir(dir)
    random_image = random.choice(dir_contents)
    return dir + random_image

def resize_dir(size=150, dir='images/'):
    for img_file in os.listdir(dir):
        img = Image.open(dir + img_file)
        width, height = img.size
        print(width, height)
        if not (width > size or height > size):
            continue

        img.thumbnail((size, size),Image.ANTIALIAS)
        img.save(dir + img_file)