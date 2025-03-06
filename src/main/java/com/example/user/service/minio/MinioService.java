package com.example.user.service.minio;

import com.example.user.client.UserClient;
import com.example.user.config.MinioConfig;
import com.example.user.dto.UserDto;
import com.example.user.mapper.UserMapper;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import io.minio.RemoveObjectArgs;
import io.minio.errors.*;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class MinioService implements ObjectStorage {

    private final MinioClient client;
    private final UserMapper userMapper;
    private final UserClient userClient;

    public MinioService(MinioConfig config, UserMapper userMapper, UserClient userClient) {
        this.client = config.initMinioClient();
        this.userMapper = userMapper;
        this.userClient = userClient;
    }


    @Override
    public String uploadFile(String bucketName, String directory, MultipartFile file) {
        String fileName = UUID.randomUUID().toString();

        try (InputStream inputStream = file.getInputStream()) { // Try-with-resources 적용
            client.putObject(PutObjectArgs.builder()
                    .object(directory + "/" + fileName)
                    .contentType(file.getContentType())
                    .bucket(bucketName)
                    .stream(inputStream, file.getSize(), -1)
                    .build());
        } catch (ServerException | ErrorResponseException | InsufficientDataException | IOException |
                 NoSuchAlgorithmException | InvalidKeyException | InvalidResponseException | XmlParserException |
                 InternalException e) {
            throw new RuntimeException(e);
        }

        return fileName;
    }

    @Override
    public void deleteFile(String bucketName, String directory, String fileName) {
        try {
            client.removeObject(RemoveObjectArgs.builder().bucket(bucketName).object(directory + "/" + fileName).build());
        } catch (ServerException | ErrorResponseException | InsufficientDataException | IOException |
                 NoSuchAlgorithmException | InvalidKeyException | InvalidResponseException | XmlParserException |
                 InternalException e) {
            throw new RuntimeException(e);
        }
    }

    public void test() {
    }
}
