FROM python:3

#ENV VIRTUAL_ENV=/opt/venv
#RUN python3 -m venv $VIRTUAL_ENV
#ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN  mkdir WORK_REPO
RUN  cd  WORK_REPO
WORKDIR  /WORK_REPO

COPY requirements.txt requirements.txt
ADD certstream_filter.py .
RUN pip3 install -r requirements.txt
RUN pip3 install git+https://github.com/richardpenman/whois.git
RUN touch certstream_filter.txt
RUN chmod 777 certstream_filter.txt

# Add a new user "john" with user id 8877
RUN useradd -u 8877 john
# Change to non-root privilege
USER john

CMD ["python", "-u", "certstream_filter.py"]
