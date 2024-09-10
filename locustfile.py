from locust import HttpUser, TaskSet, task, between


class UserBehavior(TaskSet):
    @task(1)
    def log_sources(self):
        self.client.get("/sources/")

    @task(2)
    def log_source(self):
        self.client.get("/source/1/")

    @task(3)
    def add_log_source(self):
        self.client.post(
            "/add-source/",
            data={
                "name": "Test Source",
                "description": "Cool Log Source",
                "hostname": "http://example.com",
                "ip_address": "127.0.0.1",
                "protocol": "http",
            },
        )

    @task(4)
    def delete_log_source(self):
        self.client.post("/delete-source/", data={"id": 1})

    @task(5)
    def report(self):
        self.client.get("/report/1/")

    @task(6)
    def reports(self):
        self.client.get("/reports/")

    @task(7)
    def alerts(self):
        self.client.get("/alerts/")

    @task(8)
    def alert(self):
        self.client.get("/alert/1/")

    @task(9)
    def log_file(self):
        self.client.get("/log-file/1/")

    @task(10)
    def read_log(self):
        self.client.get("/read-file/1/")

    @task(11)
    def run_detectors(self):
        self.client.get("/run-detectors/1/")

    @task(12)
    def dashboard(self):
        self.client.get("/")


class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    wait_time = between(1, 5)
