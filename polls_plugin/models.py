from django.db import models


class Vote(models.Model):
    VOTE_CHOICES_CLASS = [
        ("NA", "NA"),  # not available
        ("Mild", "Mild"),
        ("Moderate", "Moderate"),
        ("Severe", "Severe"),
        ("Critical", "Critical"),
    ]

    VOTE_CHOICES_NUM = [
        ("NV", "NV"),  # no value
        ("0", "0"),
        ("1", "1"),
        ("2", "2"),
        ("3", "3"),
        ("4", "4"),
        ("5", "5"),
        ("6", "6"),
        ("7", "7"),
        ("8", "8"),
        ("9", "9"),
        ("10", "10"),
    ]

    finding_id = models.IntegerField()
    user_id = models.IntegerField()
    vote_class = models.CharField(max_length=10, choices=VOTE_CHOICES_CLASS)
    vote_num = models.CharField(max_length=10, choices=VOTE_CHOICES_NUM)
    timestamp = models.DateTimeField(auto_now_add=False)

    class Meta:
        db_table = "votes"
        indexes = [
            models.Index(fields=["finding_id", "user_id"]),
        ]
