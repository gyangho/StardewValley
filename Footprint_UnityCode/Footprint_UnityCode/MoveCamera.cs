using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UI;

public class MoveCamera : MonoBehaviour
{
    public Transform target;

    public Button p1Button;
    public Button p2Button;
    public Button p3Button;

    public Transform Player1;
    public Transform Player2;
    public Transform Player3;

    public Camera MainCamera;

    private Text location;
    
    private void Start()
    {
        // ��ư Ŭ�� �̺�Ʈ �ڵ鷯
        p1Button.onClick.AddListener(() => SetMainCameraTarget(Player1));
        p2Button.onClick.AddListener(() => SetMainCameraTarget(Player2));
        p3Button.onClick.AddListener(() => SetMainCameraTarget(Player3));

        MainCamera = GetComponent<Camera>();
    }

    private void SetMainCameraTarget(Transform targetPlayer)
    {
        //�÷��̾ �°� ī�޶� ��Ŀ��
        MainCamera.transform.position = targetPlayer.position;
        target = targetPlayer;
    }

    void LateUpdate()
    {
        transform.position = new Vector3(target.position.x, target.position.y, -10f);
        
    }
}
