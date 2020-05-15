from setuptools import setup, find_packages

install_requires = [
      'pefile'
]

test_requires = [
      'pytest',
      'pytest-cov'
]

setup(name='dfrus',
      version='0.0.4',
      # description='',
      url='http://bitbucket.org/dfint/dfrus-py',
      author='insolor',
      author_email='insolor@gmail.com',
      license='MIT',
      packages=find_packages(),
      install_requires=install_requires,
      test_requires=test_requires,
      zip_safe=False)
