import os
import pandas as pd

class DtcDataOperations:

    def __init__(self):
        self.input_dataset_file_path = 'src/res/datasets/combined.csv'
        self.input_dataset_info_file_path = 'src/outputs/datasets/detection/input_dataset_info.txt'
        self.output_dataset_file_path = 'src/outputs/datasets/detection/combined_output.csv'
        self.output_dataset_info_file_path = 'src/outputs/datasets/detection/output_dataset_info.txt'

        for path in [
            self.input_dataset_file_path,
            self.input_dataset_info_file_path,
            self.output_dataset_file_path,
            self.output_dataset_info_file_path
        ]:
            os.makedirs(os.path.dirname(path), exist_ok=True)

        self.df = pd.read_csv(self.input_dataset_file_path)

    def dataAnalysis(self, file_path):
        total_records = len(self.df)
        label_counts = self.df['Label'].value_counts(dropna=False)
        columns_info = self.df.dtypes

        with open(file_path, 'w') as f:
            f.write(f"General Dataset Information\n")
            f.write(f"Total number of records: {total_records}\n\n")
            
            f.write("Label Distribution\n")
            for label, count in label_counts.items():
                f.write(f"{label}: {count} ({count / total_records * 100:.2f}%)\n")
            
            f.write("\nColumn Data Types\n")
            for col, dtype in columns_info.items():
                f.write(f"{col}: {dtype}\n")

        print(f"Data analysis saved in file '{file_path}'.")

    def filterData(self):
        selected_columns = [
            'TotBytes',
            'SrcBytes',
            'DstBytes',
            'TotPkts',
            'SrcPkts',
            'DstPkts',
            'Rate',
            'SrcRate',
            'DstRate',
            'Dur',
            'RunTime',
            'TcpRtt',
            'SynAck',
            'AckDat',
            'Seq',
            'Proto',
            'Label'
        ]

        missing_columns = [col for col in selected_columns if col not in self.df.columns]
        if missing_columns:
            print(f"Warning: The following columns were not found in file '{self.input_dataset_file_path}':", missing_columns)

        existing_columns = [col for col in selected_columns if col in self.df.columns]
        self.df = self.df[self.df['Attack Type'] != 'UDPScan']
        self.df = self.df[existing_columns]
        self.df.to_csv(self.output_dataset_file_path, index=False)
        print(f"Selected columns are saved in file '{self.output_dataset_file_path}'.")
        return self.df

    def allSteps(self):
        dpFD = DtcDataOperations()
        dpFD.dataAnalysis(self.input_dataset_info_file_path)
        dpFD.filterData()
        dpFD.dataAnalysis(self.output_dataset_info_file_path)