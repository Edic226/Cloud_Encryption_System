from django.db import models
from user_system.models import UserInfo


# Create your models here.
class DataInfo(models.Model):
    tittle_hash = models.CharField('标题:', max_length=128)
    plaintext_hash = models.TextField('明文哈希值:')
    chipertext_hash = models.TextField('密文哈希值:')
    encode_ways = models.CharField('加密方式:', max_length=10)
    user = models.ForeignKey(UserInfo, on_delete=models.CASCADE)
