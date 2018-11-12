from setuptools import setup

with open('requirements.txt', 'r') as f:
    requirements = [item for item in f.read().split('\n') if item]

setup(
      name='hybrid_analysis_api',
      version='0.1.0',
      description='Hybrid Analysis API Handler',
      url='https://github.com/0bscurec0de/hybrid_analysis_api.git',
      author='Felipe Duarte',
      author_email='efelipe.duartep@gmail.com',
      license='GNU v3',
      packages=['hybrid_analysis_api'],
      install_requires=requirements,
      zip_safe=False
)
