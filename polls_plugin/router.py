class PollsRouter:
    app_label = "polls_plugin"

    def db_for_read(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return "polls"
        return "default"

    def db_for_write(self, model, **hints):
        if model._meta.app_label == self.app_label:
            return "polls"
        return "default"

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == self.app_label:
            return db == "polls"
        return db == "default"
