FROM python

COPY ./requirements.txt /tmp/console_requirements.txt
RUN python -m pip install -r /tmp/console_requirements.txt
RUN python -m pip install gunicorn

