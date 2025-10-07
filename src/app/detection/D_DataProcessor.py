import os
import pandas as pd

class D_DataProcessor:

    def __init__(self):
        self.input_dataset_file_path = 'src/res/datasets/Combined.csv'
        self.dataset_info_file_path = 'src/outputs/datasets/detection/input_dataset_info.txt'
        self.output_dataset_file_path = 'src/outputs/datasets/detection/Combined_output.csv'

        for path in [
            self.input_dataset_file_path,
            self.dataset_info_file_path,
            self.output_dataset_file_path
        ]:
            os.makedirs(os.path.dirname(path), exist_ok=True)

        self.df = pd.read_csv(self.input_dataset_file_path)

    def dataAnalysis(self):
        total_records = len(self.df)
        label_counts = self.df['Label'].value_counts(dropna=False)
        columns_info = self.df.dtypes

        with open(self.dataset_info_file_path, 'w') as f:
            f.write(f"General Dataset Information\n")
            f.write(f"Total number of records: {total_records}\n\n")
            
            f.write("Label Distribution\n")
            for label, count in label_counts.items():
                f.write(f"{label}: {count} ({count / total_records * 100:.2f}%)\n")
            
            f.write("\nColumn Data Types\n")
            for col, dtype in columns_info.items():
                f.write(f"{col}: {dtype}\n")

        print(f"Data analysis saved in file '{self.dataset_info_file_path}'.")

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
        df_selected = self.df[existing_columns]
        df_selected.to_csv(self.output_dataset_file_path, index=False)
        print(f"Selected columns are saved in file '{self.output_dataset_file_path}'.")
        return df_selected

    def allSteps(self):
        dpFD = D_DataProcessor()
        dpFD.dataAnalysis()
        dpFD.filterData()