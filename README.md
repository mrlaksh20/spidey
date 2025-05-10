### Installation Instructions

To install and run the tool, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/lakshlucky20/spidey
    ```

2. Navigate to the project directory:
    ```bash
    cd spidey
    ```

3. Install the dependencies:
    ```bash
    go mod tidy
    ```

4. Run the tool:
    ```bash
    bash run.sh
    ```

Now you are good to go! 🚀


```         
               <-----------------------------------STRUCTURE------------------------------------>

 spidey/
├── go.mod
├── go.sum
├── run.sh
├── pkg/
│   ├── 404_1.go
│   ├── 404_2.go
│   ├── 404_3.go
│   ├── 404_choose.sh
│   ├── active.sh
│   ├── cat_choose.go
│   ├── cat_multi.go
│   ├── cat_one.go
│   ├── probe.go
│   ├── scan.go               <-- 🔥 Final scan engine
│   └── urls_all.go
├── regex_patterns/
│   ├── regex.json            <-- 💡 Loaded into memory ONCE
│   └── regex.json.bak
├── reports/
│   ├── example.com_all.txt
│   ├── example.com_active.txt
│   └── example.com_results.json   <-- ✅ Final juicy output
├── analytics/
│   ├── example.com/
│   │   ├── config.txt
│   │   ├── css.txt
│   │   ├── html.txt
│   │   ├── js.txt
│   │   ├── json.txt
│   │   ├── otherfiles.txt
│   │   └── pdf.txt
│   └── example.com_deduplicates/
│       ├── config.txt
│       ├── css.txt
│       ├── html.txt
│       ├── js.txt
│       ├── json.txt
│       ├── otherfiles.txt
│       └── pdf.txt
├── probe/
│   ├── example.com/
│   │   ├── js200.txt
│   │   ├── json403.txt
│   │   ├── html404.txt
│   │   └── ...many response-code-named files
│   └── example.com_deduplicates/
│       ├── ...
├── snapurls/
│   └── example.com_js200_scan.txt   <-- 🕵️‍♂️ Extracted snapshot URLs
└── README.md                         <-- (Optional but you should flex this 😎)
```


