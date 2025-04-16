document.addEventListener("change", function (event) {
    if (event.target.classList.contains("vote-dropdown")) {
        const dropdown = event.target;
        const findingId = dropdown.dataset.findingId;
        const vote = dropdown.value;

        const VOTE_CHOICES_CLASS = ["NA", "Mild", "Moderate", "Severe", "Critical"];
        const VOTE_CHOICES_NUM = ["NV", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"];

        let vote_type = "unknown"

        if (VOTE_CHOICES_CLASS.includes(vote)) {
            vote_type = "class";
        } else if (VOTE_CHOICES_NUM.includes(vote)) {
            vote_type = "num";
        }

        if (vote_type !== "unknown") {
            dropdown.disabled = true;

            fetch("/finding/save_vote/", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": document.querySelector("[name=csrfmiddlewaretoken]").value,
                },
                body: JSON.stringify({ finding_id: findingId, vote: vote, vote_type: vote_type }),
            })
                .then((response) => {
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    return response.json();
                })
                .then((data) => {
                    console.log("Vote saved:", data);
                })
                .catch((error) => {
                    console.error("Error saving vote:", error);
                    alert("Error saving the vote. Please try again.");
                })
                .finally(() => {
                    dropdown.disabled = false;
                });
        }
    }
});