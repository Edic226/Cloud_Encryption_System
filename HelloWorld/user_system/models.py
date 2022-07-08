from django.db import models


# Create your models here.
class UserInfo(models.Model):
    username = models.CharField('用户名', max_length=30, unique=True)
    password = models.CharField('密码',  max_length=128)
    created_time = models.DateTimeField('创建时间', auto_now_add=True)
    updated_time = models.DateTimeField('更新时间', auto_now=True)
    private_key = models.CharField('公钥', max_length=64, default='')
    public_key = models.CharField('私钥', max_length=128, default='')

    def __str__(self):
        return 'username' + self.username
