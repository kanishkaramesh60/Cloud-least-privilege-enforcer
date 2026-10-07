let polling = null;


async function startPipeline() {

    const response =
        await fetch(
            "/api/start",
            {
                method: "POST"
            }
        );

    const data =
        await response.json();

    console.log(data);

    if (data.success) {

        polling =
            setInterval(
                updateDashboard,
                1000
            );

    }

}


async function stopPipeline() {

    await fetch(
        "/api/stop",
        {
            method: "POST"
        }
    );

}


async function updateDashboard() {

    const response =
        await fetch(
            "/api/status"
        );

    const data =
        await response.json();


    document
        .getElementById("status")
        .innerText =
        data.status;


    document
        .getElementById("consoleOutput")
        .innerText =
        data.output.join("\n");


    if (!data.running) {

        clearInterval(
            polling
        );

        loadReports();

    }

}


async function loadReports() {

    const response =
        await fetch(
            "/api/reports"
        );

    const data =
        await response.json();


    const container =
        document.getElementById(
            "reports"
        );


    if (data.length === 0) {

        container.innerHTML =
            "No reports available.";

        return;

    }


    container.innerHTML = "";


    data.forEach(
        report => {

            const div =
                document.createElement(
                    "div"
                );

            div.className =
                "report-item";

            div.innerText =
                report.name;

            container.appendChild(
                div
            );

        }
    );

}