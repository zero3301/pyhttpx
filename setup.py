from setuptools import setup, find_packages

setup(
    name = "pyhttpx",   #这里是pip项目发布的名称
    version = "1.1.4",  #版本号，数值大的会优先被pip
    keywords = ["pip", "pyhttpx"],			#关键字
    description = "HTTP library.",	#描述
    long_description = "3301's private utils.",
    license = "MIT Licence",		# 许可证

    url = "https://github.com/zero3301/pyhttpx",     #项目相关文件地址，一般是github项目地址即可
    author = "zan3301",			# 作者
    author_email = "1114135928@qq.com",
    package_data={
        # 包含文件后缀
        '': ['*.pyd','*.so']},
    packages = find_packages(),
    include_package_data = False,
    platforms = "any",
    install_requires = ["cryptography==36.0.1", "rsa==4.8", "pyOpenSSL==21.0.0"]

)
