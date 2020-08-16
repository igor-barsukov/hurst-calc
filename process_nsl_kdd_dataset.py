import arff # https://github.com/renatopp/liac-arff
import numpy as np

def main():
    print("prepare data: ")
    train_file = open('D:/Aspirantura/ML datasets/NSLKDD-Dataset/DOS -d/KDDTrain20DOS.arff', 'r')
    train_data = arff.load(train_file)
    np_arr_train = np.array(train_data['data'])

    # print(np_arr_train) # [[entry 0 of 42 features], [entry 1 of 42 features], [entry 3 of 42 features], .....]
    # print(np_arr_train[:,0]) # [values of 0 feature]  ->  rank 1 array
    # print(np_arr_train[0,:]) # [entry 0 of 42 features]  ->  rank 1 array


    # np_arr_train, np_arr_train_flag = np.vsplit(np_arr_train.T, [41]) # last column - attack/not attack flag
    # print(np_arr_train_flag)
    # print("arr train shape - " + str(np_arr_train.shape))
    # print("arr train flag shape - " + str(np_arr_train_flag.shape))

    # extract_feature_values(0, 'duration_normal', np_arr_train, 0)
    extract_feature_values(0, 'duration_attack', np_arr_train, 1)
    # extract_feature_values(0, 'duration_full', np_arr_train, 'all')
    # extract_feature_values(1, 'src_bytes_normal', np_arr_train, 0)
    extract_feature_values(1, 'src_bytes_attack', np_arr_train, 1)
    extract_feature_values(1, 'src_bytes_full', np_arr_train, 'all')
    # extract_feature_values(2, 'dst_bytes_normal', np_arr_train, 0)
    extract_feature_values(2, 'dst_bytes_attack', np_arr_train, 1)
    extract_feature_values(2, 'dst_bytes_full', np_arr_train, 'all')
    # extract_feature_values(40, 'flag_normal', np_arr_train, 0)
    extract_feature_values(40, 'flag_attack', np_arr_train, 1)
    extract_feature_values(40, 'flag_full', np_arr_train, 'all')
    # extract_feature_values(21, 'serror_rate_normal', np_arr_train, 0)
    extract_feature_values(21, 'serror_rate_attack', np_arr_train, 1)
    extract_feature_values(21, 'serror_rate_full', np_arr_train, 'all')
    # extract_feature_values(22, 'srv_serror_rate_normal', np_arr_train, 0)
    extract_feature_values(22, 'srv_serror_rate_attack', np_arr_train, 1)
    extract_feature_values(22, 'srv_serror_rate_full', np_arr_train, 'all')
    # extract_feature_values(23, 'rerror_rate_normal', np_arr_train, 0)
    extract_feature_values(23, 'rerror_rate_attack', np_arr_train, 1)
    extract_feature_values(23, 'rerror_rate_full', np_arr_train, 'all')
    # extract_feature_values(24, 'srv_rerror_rate_normal', np_arr_train, 0)
    extract_feature_values(24, 'srv_rerror_rate_attack', np_arr_train, 1)
    extract_feature_values(24, 'srv_rerror_rate_full', np_arr_train, 'all')
    extract_feature_values(25, 'same_srv_rate_normal', np_arr_train, 0)
    extract_feature_values(25, 'same_srv_rate_attack', np_arr_train, 1)
    extract_feature_values(25, 'same_srv_rate_full', np_arr_train, 'all')
    extract_feature_values(26, 'diff_srv_rate_normal', np_arr_train, 0)
    extract_feature_values(26, 'diff_srv_rate_attack', np_arr_train, 1)
    extract_feature_values(26, 'diff_srv_rate_full', np_arr_train, 'all')

    extract_feature_values(34, 'dst_host_serror_rate_normal', np_arr_train, 0)
    extract_feature_values(34, 'dst_host_serror_rate_attack', np_arr_train, 1)
    extract_feature_values(34, 'dst_host_serror_rate_full', np_arr_train, 'all')
    extract_feature_values(35, 'dst_host_srv_serror_rate_normal', np_arr_train, 0)
    extract_feature_values(35, 'dst_host_srv_serror_rate_attack', np_arr_train, 1)
    extract_feature_values(35, 'dst_host_srv_serror_rate_full', np_arr_train, 'all')
    extract_feature_values(36, 'dst_host_rerror_rate_normal', np_arr_train, 0)
    extract_feature_values(36, 'dst_host_rerror_rate_attack', np_arr_train, 1)
    extract_feature_values(36, 'dst_host_rerror_rate_full', np_arr_train, 'all')
    extract_feature_values(37, 'dst_host_srv_rerror_rate_normal', np_arr_train, 0)
    extract_feature_values(37, 'dst_host_srv_rerror_rate_attack', np_arr_train, 1)
    extract_feature_values(37, 'dst_host_srv_rerror_rate_full', np_arr_train, 'all')

    # a = np.arange(20.0).reshape(4,5)
    # print(a.shape)
    # print(a[:,4])

# flag_type: 0 - normal, 1 - attack
def extract_feature_values(feature_num, feature_name, dataset, flag_type):
    arr_x_attack_flag = dataset[:, 41]
    print("X attack flag arr shape ", str(arr_x_attack_flag.shape))
    if flag_type == 0:
        # normal flag
        filter_by_flag = arr_x_attack_flag.astype(int) < 1
    elif flag_type == 1:
        # attack flag
        filter_by_flag = arr_x_attack_flag.astype(int) > 0
    else:
        # normal+attack
        filter_by_flag = arr_x_attack_flag.astype(int) >= 0 # all True
    # print(filter_normal_flag)
    extracted_feature = dataset[:,feature_num]
    # print("extracted_feature ", extracted_feature)
    extracted_feature_by_filter = extracted_feature[filter_by_flag] # filtering using boolean mask - https://www.w3schools.com/python/numpy_array_filter.asp
    converted_float = extracted_feature_by_filter.astype(float) # can't pass a string representation of a float into, so need this double conversion
    converted_int = converted_float.astype(int)
    np.savetxt(feature_name + '.csv', converted_int, fmt="%s")
    print("extracted feature shape ", extracted_feature_by_filter.shape)
    return extracted_feature_by_filter

if __name__ == '__main__':
    main()
